mod error;
mod issue;
mod redeem;
mod replace;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi, ConversionError, PartialAddress};
use clap::Clap;
use error::Error;
use futures::future::try_join_all;
use git_version::git_version;
use log::*;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    substrate_subxt::{PairSigner, Signer},
    AccountId, BtcAddress, CollateralBalancesPallet, ErrorCode as InterBtcErrorCode, ExchangeRateOraclePallet,
    FeePallet, FixedPointNumber,
    FixedPointTraits::*,
    FixedU128, H256Le, InterBtcParachain, InterBtcRuntime, IssueRequestStatus, RedeemPallet,
    StatusCode as InterBtcStatusCode, TimestampPallet,
};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::{convert::TryInto, time::Duration};

#[derive(Debug, Encode, Decode)]
struct BtcAddressFromStr(BtcAddress);
impl std::str::FromStr for BtcAddressFromStr {
    type Err = ConversionError;
    fn from_str(btc_address: &str) -> Result<Self, Self::Err> {
        Ok(BtcAddressFromStr(PartialAddress::decode_str(btc_address)?))
    }
}

#[derive(Debug, Encode, Decode)]
struct InterBtcStatusCodeFromStr(InterBtcStatusCode);
impl std::str::FromStr for InterBtcStatusCodeFromStr {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "running" => Ok(InterBtcStatusCodeFromStr(InterBtcStatusCode::Running)),
            "shutdown" => Ok(InterBtcStatusCodeFromStr(InterBtcStatusCode::Shutdown)),
            "error" => Ok(InterBtcStatusCodeFromStr(InterBtcStatusCode::Error)),
            _ => Err("Could not parse input as StatusCode".to_string()),
        }
    }
}

#[derive(Debug, Encode, Decode)]
struct H256LeFromStr(H256Le);
impl std::str::FromStr for H256LeFromStr {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        Ok(H256LeFromStr(H256Le::from_hex_le(code)))
    }
}

#[derive(Debug, Encode, Decode)]
struct InterBtcErrorCodeFromStr(InterBtcErrorCode);
impl std::str::FromStr for InterBtcErrorCodeFromStr {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "none" => Ok(InterBtcErrorCodeFromStr(InterBtcErrorCode::None)),
            "no-data-btc-relay" => Ok(InterBtcErrorCodeFromStr(InterBtcErrorCode::NoDataBTCRelay)),
            "invalid-btc-relay" => Ok(InterBtcErrorCodeFromStr(InterBtcErrorCode::InvalidBTCRelay)),
            "oracle-offline" => Ok(InterBtcErrorCodeFromStr(InterBtcErrorCode::OracleOffline)),
            _ => Err("Could not parse input as ErrorCode".to_string()),
        }
    }
}

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    btc_parachain_url: String,

    /// keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    #[clap(subcommand)]
    subcmd: SubCommand,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    connection_timeout_ms: u64,
}

#[derive(Clap)]
enum SubCommand {
    /// Set the exchange rate.
    SetExchangeRate(SetExchangeRateInfo),
    /// Add a new authorized oracle
    InsertAuthorizedOracle(InsertAuthorizedOracleInfo),
    /// Get the current exchange rate.
    GetExchangeRate,
    /// Set the current estimated bitcoin transaction fees.
    SetBtcTxFees(SetBtcTxFeesInfo),
    /// Get the current estimated bitcoin transaction fees.
    GetBtcTxFees,
    /// Get the time as reported by the chain.
    GetCurrentTime,
    /// Register a new vault using the global keyring.
    RegisterVault(RegisterVaultInfo),
    /// Request issuance  and transfer to vault.
    RequestIssue(RequestIssueInfo),
    /// Send BTC to an address.
    SendBitcoin(SendBitcoinInfo),
    /// Request that issued tokens be burned to redeem BTC.
    RequestRedeem(RequestRedeemInfo),
    /// Send BTC to user, must be called by vault.
    ExecuteRedeem(ExecuteRedeemInfo),
    /// Request another vault to takeover.
    RequestReplace(RequestReplaceInfo),
    /// Accept replace request of another vault.
    AcceptReplace(AcceptReplaceInfo),
    /// Accept replace request of another vault.
    ExecuteReplace(ExecuteReplaceInfo),
    /// Set issue period.
    SetIssuePeriod(SetIssuePeriodInfo),
    /// Set redeem period.
    SetRedeemPeriod(SetRedeemPeriodInfo),
    /// Set replace period.
    SetReplacePeriod(SetReplacePeriodInfo),
    /// Transfer collateral.
    FundAccounts(FundAccountsInfo),
}

#[derive(Clap)]
struct SetExchangeRateInfo {
    /// This value, when multiplied by the conversion factor (i.e. 10**8 / 10**10 for BTC/DOT),
    /// represents the base exchange rate - i.e. (Planck per Satoshi).
    #[clap(long, default_value = "1")]
    exchange_rate: u128,
}

#[derive(Clap)]
struct InsertAuthorizedOracleInfo {
    #[clap(long, default_value = "charlie")]
    account: AccountKeyring,
    #[clap(long, default_value = "Charlie")]
    name: String,
}

#[derive(Clap)]
struct SetBtcTxFeesInfo {
    /// The estimated Satoshis per bytes to get included in the next block (~10 min)
    #[clap(long, default_value = "100")]
    fast: u32,

    /// The estimated Satoshis per bytes to get included in the next 3 blocks (~half hour)
    #[clap(long, default_value = "200")]
    half: u32,

    /// The estimated Satoshis per bytes to get included in the next 6 blocks (~hour)
    #[clap(long, default_value = "300")]
    hour: u32,
}

#[derive(Clap)]
struct RegisterVaultInfo {
    /// Collateral to secure position.
    #[clap(long, default_value = "100000")]
    collateral: u128,
}

#[derive(Clap)]
struct RequestIssueInfo {
    /// Amount  to issue.
    #[clap(long, default_value = "100000")]
    issue_amount: u128,

    /// Griefing collateral for request. If unset, the necessary amount will be calculated calculated automatically.
    #[clap(long)]
    griefing_collateral: Option<u128>,

    /// Vault keyring to derive `vault_id`.
    #[clap(long)]
    vault: AccountId,

    /// Do not transfer BTC or execute the issue request.
    #[clap(long)]
    no_execute: bool,
}

#[derive(Clap)]
struct SendBitcoinInfo {
    /// Recipient Bitcoin address.
    #[clap(long)]
    btc_address: Option<BtcAddressFromStr>,

    /// Amount of BTC to transfer.
    #[clap(long, default_value = "0")]
    satoshis: u128,

    /// Issue id for the issue request.
    #[clap(long)]
    issue_id: Option<H256>,
}

#[derive(Clap)]
struct SetIssuePeriodInfo {
    /// Period after issue requests expire.
    #[clap(long)]
    period: u32,
}

#[derive(Clap)]
struct SetRedeemPeriodInfo {
    /// Period after redeem requests expire.
    #[clap(long)]
    period: u32,
}

#[derive(Clap)]
struct SetReplacePeriodInfo {
    /// Period after replace requests expire.
    #[clap(long)]
    period: u32,
}

#[derive(Clap)]
struct RequestRedeemInfo {
    /// Amount  to redeem.
    #[clap(long, default_value = "500")]
    redeem_amount: u128,

    /// Bitcoin address for vault to send funds.
    #[clap(long)]
    btc_address: BtcAddressFromStr,

    /// Vault keyring to derive `vault_id`.
    #[clap(long, default_value = "bob")]
    vault: AccountKeyring,
}

#[derive(Clap)]
struct ExecuteRedeemInfo {
    /// Redeem id for the redeem request.
    #[clap(long)]
    redeem_id: H256,
}

#[derive(Clap)]
struct RequestReplaceInfo {
    /// Amount  to issue.
    #[clap(long, default_value = "100000")]
    replace_amount: u128,

    /// Griefing collateral for request.
    #[clap(long, default_value = "100")]
    griefing_collateral: u128,
}

#[derive(Clap)]
struct AcceptReplaceInfo {
    /// Old vault to replace.
    #[clap(long)]
    old_vault: AccountId,

    /// Amount  to replace.
    #[clap(long)]
    amount_btc: u128,

    /// Collateral used to back replace.
    #[clap(long)]
    collateral: u128,
}

#[derive(Clap)]
struct ExecuteReplaceInfo {
    /// Replace id for the replace request.
    #[clap(long)]
    replace_id: H256,
}

#[derive(Clap, Encode, Decode, Debug)]
struct RequestReplaceJsonRpcRequest {
    /// Amount to replace.
    #[clap(long, default_value = "10000")]
    amount: u128,

    /// Griefing collateral for request.
    #[clap(long, default_value = "10000")]
    griefing_collateral: u128,
}

#[derive(Clap, Encode, Decode, Debug)]
struct RegisterVaultJsonRpcRequest {
    /// Collateral to secure position.
    #[clap(long, default_value = "100000")]
    collateral: u128,

    /// Bitcoin address for vault to receive funds.
    #[clap(long)]
    btc_address: BtcAddressFromStr,
}

#[derive(Clap, Encode, Decode, Debug)]
struct DepositCollateralJsonRpcRequest {
    /// Amount to lock.
    #[clap(long, default_value = "10000")]
    amount: u128,
}

#[derive(Clap, Encode, Decode, Debug)]
struct WithdrawCollateralJsonRpcRequest {
    /// Amount to withdraw.
    #[clap(long, default_value = "10000")]
    amount: u128,
}

#[derive(Clap, Encode, Decode, Debug)]
struct UpdateBtcAddressJsonRpcRequest {
    /// New bitcoin address to set.
    #[clap(long)]
    address: BtcAddressFromStr,
}

#[derive(Clap, Encode, Decode, Debug)]
struct WithdrawReplaceJsonRpcRequest {
    /// ID of the replace request to withdraw.
    #[clap(long)]
    replace_id: H256,
}

#[derive(Clap, Encode, Decode, Debug)]
struct SuggestStatusUpdateJsonRpcRequest {
    /// Deposit.
    #[clap(long)]
    deposit: u128,

    /// Status code: running, shutdown or error.
    #[clap(long)]
    status_code: InterBtcStatusCodeFromStr,

    /// Error code: none, no-data-btc-relay, invalid-btc-relay, oracle-offline or liquidation.
    #[clap(long)]
    add_error: Option<InterBtcErrorCodeFromStr>,

    /// Error code: none, no-data-btc-relay, invalid-btc-relay, oracle-offline or liquidation.
    #[clap(long)]
    remove_error: Option<InterBtcErrorCodeFromStr>,

    /// Hash of the block.
    #[clap(long)]
    block_hash: Option<H256LeFromStr>,

    /// Message.
    #[clap(long)]
    message: String,
}

#[derive(Clap, Encode, Decode, Debug)]
struct RegisterStakedRelayerJsonRpcRequest {
    /// Amount to stake.
    #[clap(long)]
    stake: u128,
}

#[derive(Clap, Encode, Decode, Debug)]
struct VoteOnStatusUpdateJsonRpcRequest {
    /// Id of the status update.
    #[clap(long)]
    pub status_update_id: u64,

    /// Whether or not to approve the status update.
    #[clap(long, parse(try_from_str))]
    pub approve: bool,
}

#[derive(Clap, Encode, Decode, Debug)]
struct FundAccountsInfo {
    /// Accounts to fund
    #[clap(long)]
    pub accounts: Vec<AccountId>,

    /// DOT amount
    #[clap(long)]
    pub amount: u128,
}

async fn get_bitcoin_core(bitcoin_opts: bitcoin::cli::BitcoinOpts, wallet_name: String) -> Result<BitcoinCore, Error> {
    let bitcoin_core = bitcoin_opts.new_client(Some(wallet_name.to_string()))?;
    bitcoin_core.create_or_load_wallet().await?;
    Ok(bitcoin_core)
}

/// Generates testdata to be used on a development environment of the BTC Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let (key_pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<InterBtcRuntime, _>::new(key_pair);
    let parachain_rpc = InterBtcParachain::from_url_with_retry(
        &opts.btc_parachain_url,
        signer,
        Duration::from_millis(opts.connection_timeout_ms),
    )
    .await?;

    match opts.subcmd {
        SubCommand::SetExchangeRate(info) => {
            let rate = FixedU128::checked_from_rational(info.exchange_rate, 100_000).unwrap();
            parachain_rpc.set_exchange_rate_info(rate).await?;
        }
        SubCommand::InsertAuthorizedOracle(info) => {
            let key_pair = info.account.pair();
            let signer = PairSigner::<InterBtcRuntime, _>::new(key_pair);
            let oracle_id = signer.account_id().clone();
            parachain_rpc.insert_authorized_oracle(oracle_id, info.name).await?;
        }
        SubCommand::GetExchangeRate => {
            let (rate, time, delay) = parachain_rpc.get_exchange_rate_info().await?;
            println!(
                "Exchange Rate BTC/DOT: {:?}, Last Update: {}, Delay: {}",
                rate, time, delay
            );
        }
        SubCommand::SetBtcTxFees(info) => {
            parachain_rpc
                .set_btc_tx_fees_per_byte(info.fast, info.half, info.hour)
                .await?;
        }
        SubCommand::GetBtcTxFees => {
            let fees = parachain_rpc.get_btc_tx_fees_per_byte().await?;
            println!(
                "Fees per byte: fast={} half={} hour={}",
                fees.fast, fees.half, fees.hour
            );
        }
        SubCommand::GetCurrentTime => {
            println!("{}", parachain_rpc.get_time_now().await?);
        }
        SubCommand::RegisterVault(info) => {
            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            vault::register_vault(parachain_rpc, btc_rpc.get_new_public_key().await?, info.collateral).await?;
        }
        SubCommand::RequestIssue(info) => {
            let vault_id = info.vault;

            let griefing_collateral = match info.griefing_collateral {
                Some(x) => x,
                None => {
                    // calculate required amount
                    let amount_in_dot = parachain_rpc.wrapped_to_collateral(info.issue_amount).await?;
                    let required_griefing_collateral_rate = parachain_rpc.get_issue_griefing_collateral().await?;

                    // we add 0.5 before we do the final integer division to round the result we return.
                    // note that unwrapping is safe because we use a constant
                    let calc_griefing_collateral = || {
                        let rounding_addition = FixedU128::checked_from_rational(1, 2).unwrap();

                        FixedU128::checked_from_integer(amount_in_dot)?
                            .checked_mul(&required_griefing_collateral_rate)?
                            .checked_add(&rounding_addition)?
                            .into_inner()
                            .checked_div(FixedU128::accuracy())
                    };

                    let griefing_collateral = calc_griefing_collateral().ok_or(Error::MathError)?;
                    info!("Griefing collateral not set; defaulting to {}", griefing_collateral);
                    griefing_collateral
                }
            };

            let request_data =
                issue::request_issue(&parachain_rpc, info.issue_amount, griefing_collateral, vault_id).await?;

            let vault_btc_address = request_data.vault_btc_address;

            if info.no_execute {
                println!("{}", hex::encode(request_data.issue_id.as_bytes()));
                return Ok(());
            }

            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            issue::execute_issue(
                &parachain_rpc,
                &btc_rpc,
                request_data.issue_id,
                request_data.amount_btc,
                vault_btc_address,
            )
            .await?;
        }
        SubCommand::SendBitcoin(info) => {
            let (btc_address, satoshis) = if let Some(issue_id) = info.issue_id {
                // gets the data from on-chain
                let issue_request = issue::get_issue_by_id(&parachain_rpc, issue_id).await?;
                if matches!(issue_request.status, IssueRequestStatus::Completed(_)) {
                    return Err(Error::IssueCompleted);
                } else if matches!(issue_request.status, IssueRequestStatus::Cancelled) {
                    return Err(Error::IssueCancelled);
                }

                (issue_request.btc_address, issue_request.amount + issue_request.fee)
            } else {
                // expects cli configuration
                let btc_address = info.btc_address.ok_or(Error::ExpectedBitcoinAddress)?.0;
                (btc_address, info.satoshis)
            };

            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            let tx_metadata = btc_rpc
                .send_to_address(btc_address, satoshis.try_into().unwrap(), None, 1)
                .await?;

            println!("{}", tx_metadata.txid);
        }
        SubCommand::RequestRedeem(info) => {
            let redeem_id = redeem::request_redeem(
                &parachain_rpc,
                info.redeem_amount,
                info.btc_address.0,
                info.vault.to_account_id(),
            )
            .await?;
            println!("{}", hex::encode(redeem_id.as_bytes()));
        }
        SubCommand::ExecuteRedeem(info) => {
            let redeem_id = info.redeem_id;
            let redeem_request = parachain_rpc.get_redeem_request(redeem_id).await?;

            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            redeem::execute_redeem(
                &parachain_rpc,
                &btc_rpc,
                redeem_id,
                redeem_request.amount_btc,
                redeem_request.btc_address,
            )
            .await?;
        }
        SubCommand::RequestReplace(info) => {
            replace::request_replace(&parachain_rpc, info.replace_amount, info.griefing_collateral).await?;
        }
        SubCommand::AcceptReplace(info) => {
            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            replace::accept_replace(
                &parachain_rpc,
                &btc_rpc,
                info.old_vault,
                info.amount_btc,
                info.collateral,
            )
            .await?;
        }
        SubCommand::ExecuteReplace(info) => {
            let btc_rpc = get_bitcoin_core(opts.bitcoin, wallet_name).await?;
            replace::execute_replace(&parachain_rpc, &btc_rpc, info.replace_id).await?;
        }
        SubCommand::SetIssuePeriod(info) => {
            issue::set_issue_period(&parachain_rpc, info.period).await?;
        }
        SubCommand::SetRedeemPeriod(info) => {
            redeem::set_redeem_period(&parachain_rpc, info.period).await?;
        }
        SubCommand::SetReplacePeriod(info) => {
            replace::set_replace_period(&parachain_rpc, info.period).await?;
        }
        SubCommand::FundAccounts(info) => {
            let parachain_rpc = &parachain_rpc;
            let futures: Vec<_> = info
                .accounts
                .iter()
                .map(|account_id| (account_id, info.amount))
                .map(|(account_id, amount)| async move { parachain_rpc.transfer_to(account_id, amount).await })
                .collect();

            try_join_all(futures).await?;
        }
    }

    Ok(())
}
