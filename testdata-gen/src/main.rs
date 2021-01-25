mod api;
mod error;
mod issue;
mod redeem;
mod replace;
mod stats;
mod utils;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi, ConversionError, PartialAddress};
use clap::Clap;
use error::Error;
use log::*;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    substrate_subxt::PairSigner, BtcAddress, ErrorCode as PolkaBtcErrorCode,
    ExchangeRateOraclePallet, FeePallet, FixedPointNumber, FixedPointTraits::*, FixedU128, H256Le,
    PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet, StakedRelayerPallet,
    StatusCode as PolkaBtcStatusCode, TimestampPallet,
};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::convert::TryInto;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Encode, Decode)]
struct BtcAddressFromStr(BtcAddress);
impl std::str::FromStr for BtcAddressFromStr {
    type Err = ConversionError;
    fn from_str(btc_address: &str) -> Result<Self, Self::Err> {
        Ok(BtcAddressFromStr(PartialAddress::decode_str(btc_address)?))
    }
}

#[derive(Debug, Encode, Decode)]
struct PolkaBtcStatusCodeFromStr(PolkaBtcStatusCode);
impl std::str::FromStr for PolkaBtcStatusCodeFromStr {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "running" => Ok(PolkaBtcStatusCodeFromStr(PolkaBtcStatusCode::Running)),
            "shutdown" => Ok(PolkaBtcStatusCodeFromStr(PolkaBtcStatusCode::Shutdown)),
            "error" => Ok(PolkaBtcStatusCodeFromStr(PolkaBtcStatusCode::Error)),
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
struct PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode);
impl std::str::FromStr for PolkaBtcErrorCodeFromStr {
    type Err = String;
    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            "none" => Ok(PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode::None)),
            "no-data-btc-relay" => Ok(PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode::NoDataBTCRelay)),
            "invalid-btc-relay" => Ok(PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode::InvalidBTCRelay)),
            "oracle-offline" => Ok(PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode::OracleOffline)),
            "liquidation" => Ok(PolkaBtcErrorCodeFromStr(PolkaBtcErrorCode::Liquidation)),
            _ => Err("Could not parse input as ErrorCode".to_string()),
        }
    }
}

/// Toolkit for generating testdata on the local BTC-Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Set the DOT to BTC exchange rate.
    SetExchangeRate(SetExchangeRateInfo),
    /// Get the current DOT to BTC exchange rate.
    GetExchangeRate,
    /// Set the current estimated bitcoin transaction fees.
    SetBtcTxFees(SetBtcTxFeesInfo),
    /// Get the current estimated bitcoin transaction fees.
    GetBtcTxFees,
    /// Get the time as reported by the chain.
    GetCurrentTime,
    /// Register a new vault using the global keyring.
    RegisterVault(RegisterVaultInfo),
    /// Request issuance of PolkaBTC and transfer to vault.
    RequestIssue(RequestIssueInfo),
    /// Send BTC to an address.
    SendBitcoin(SendBitcoinInfo),
    /// Request that PolkaBTC be burned to redeem BTC.
    RequestRedeem(RequestRedeemInfo),
    /// Send BTC to user, must be called by vault.
    ExecuteRedeem(ExecuteRedeemInfo),
    /// Request another vault to takeover.
    RequestReplace(RequestReplaceInfo),
    /// Accept replace request of another vault.
    AcceptReplace(AcceptReplaceInfo),
    /// Accept replace request of another vault.
    ExecuteReplace(ExecuteReplaceInfo),
    /// Send a API request.
    ApiCall(ApiCall),
    /// Get issue & redeem statistics.
    GetChainStats(ChainStatOpts),
    /// Print all historic events.
    DumpEvents(DumpOpts),
    /// Set issue period.
    SetIssuePeriod(SetIssuePeriodInfo),
    /// Set redeem period.
    SetRedeemPeriod(SetRedeemPeriodInfo),
    /// Set replace period.
    SetReplacePeriod(SetReplacePeriodInfo),
    /// Set relayer maturity period.
    SetRelayerMaturityPeriod(SetRelayerMaturityPeriodInfo),
}

#[derive(Clap)]
struct ApiCall {
    #[clap(subcommand)]
    subcmd: ApiSubCommand,
}

#[derive(Clap)]
enum ApiSubCommand {
    /// Send an API message to the vault
    Vault(VaultApiCommand),
    /// Send an API message to the staked relayer
    Relayer(RelayerApiCommand),
}

#[derive(Clap)]
struct VaultApiCommand {
    /// API URL.
    #[clap(long, default_value = "http://127.0.0.1:3031")]
    url: String,

    #[clap(subcommand)]
    subcmd: VaultApiSubCommand,
}

#[derive(Clap)]
struct RelayerApiCommand {
    /// API URL.
    #[clap(long, default_value = "http://127.0.0.1:3030")]
    url: String,

    #[clap(subcommand)]
    subcmd: RelayerApiSubCommand,
}

#[derive(Clap)]
enum VaultApiSubCommand {
    /// Tell the vault to place a replace request.
    RequestReplace(RequestReplaceJsonRpcRequest),
    /// Tell the vault to withdraw a replace request.
    WithdrawReplace(WithdrawReplaceJsonRpcRequest),
    /// Tell the vault to register itself.
    RegisterVault(RegisterVaultJsonRpcRequest),
    /// Tell the vault to lock additional collateral.
    LockAdditionalCollateral(LockAdditionalCollateralJsonRpcRequest),
    /// Tell the vault to withdraw collateral.
    WithdrawCollateral(WithdrawCollateralJsonRpcRequest),
    /// Tell the vault to update its BTC address.
    UpdateBtcAddress(UpdateBtcAddressJsonRpcRequest),
}

#[derive(Clap)]
enum RelayerApiSubCommand {
    /// Tell the relayer to issue a status update suggestion.
    SuggestStatusUpdate(SuggestStatusUpdateJsonRpcRequest),
    /// Tell the relayer to vote on a status update suggestion.
    VoteOnStatusUpdate(VoteOnStatusUpdateJsonRpcRequest),
    /// Tell the relayer to register itself.
    Register(RegisterStakedRelayerJsonRpcRequest),
    /// Tell the relayer to deregister itself.
    Deregister,
    /// Get the status of the parachain.
    SystemHealth,
    /// Get the account id of the relayer.
    AccountId,
}

#[derive(Debug, Copy, Clone)]
struct BitcoinNetwork(bitcoin::Network);

impl FromStr for BitcoinNetwork {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "mainnet" => Ok(BitcoinNetwork(bitcoin::Network::Bitcoin)),
            "testnet" => Ok(BitcoinNetwork(bitcoin::Network::Testnet)),
            "regtest" => Ok(BitcoinNetwork(bitcoin::Network::Regtest)),
            _ => Err(Error::UnknownBitcoinNetwork),
        }
    }
}

#[derive(Clap)]
struct DumpOpts {
    /// Print all raw events, rather than the JSON output of a select subset.
    #[clap(long)]
    raw: bool,

    /// Path of the output directory. Will be created if it does not exist.
    /// If any logs exist in this folder, they will be overwritten.
    #[clap(long, default_value = "event-logs", conflicts_with = "raw")]
    output_folder: String,
}

#[derive(Clap)]
struct ChainStatOpts {
    /// The height of the chain to start from. If left unspecified, it starts from the genesis.
    #[clap(long)]
    start: Option<u32>,

    /// The height of the chain to end at. If left unspecified, it continues at the current chain height.
    #[clap(long)]
    end: Option<u32>,
}

#[derive(Clap)]
struct SetExchangeRateInfo {
    /// Exchange rate from BTC to DOT.
    #[clap(long, default_value = "1")]
    exchange_rate: u128,
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

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
}

#[derive(Clap)]
struct RequestIssueInfo {
    /// Amount of PolkaBTC to issue.
    #[clap(long, default_value = "100000")]
    issue_amount: u128,

    /// Griefing collateral for request. If unset, the necessary amount will be calculated calculated automatically.
    #[clap(long)]
    griefing_collateral: Option<u128>,

    /// Vault keyring to derive `vault_id`.
    #[clap(long, default_value = "bob")]
    vault: AccountKeyring,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,

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

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
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
struct SetRelayerMaturityPeriodInfo {
    /// Duration of the relayer bonding period.
    #[clap(long)]
    period: u32,
}

#[derive(Clap)]
struct RequestRedeemInfo {
    /// Amount of PolkaBTC to redeem.
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

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
}

#[derive(Clap)]
struct RequestReplaceInfo {
    /// Amount of PolkaBTC to issue.
    #[clap(long, default_value = "100000")]
    replace_amount: u128,

    /// Griefing collateral for request.
    #[clap(long, default_value = "100")]
    griefing_collateral: u128,
}

#[derive(Clap)]
struct AcceptReplaceInfo {
    /// Replace id for the replace request.
    #[clap(long)]
    replace_id: H256,

    /// Collateral used to back replace.
    #[clap(long, default_value = "10000")]
    collateral: u128,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
}

#[derive(Clap)]
struct ExecuteReplaceInfo {
    /// Replace id for the replace request.
    #[clap(long)]
    replace_id: H256,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
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
struct LockAdditionalCollateralJsonRpcRequest {
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
    status_code: PolkaBtcStatusCodeFromStr,

    /// Error code: none, no-data-btc-relay, invalid-btc-relay, oracle-offline or liquidation.
    #[clap(long)]
    add_error: Option<PolkaBtcErrorCodeFromStr>,

    /// Error code: none, no-data-btc-relay, invalid-btc-relay, oracle-offline or liquidation.
    #[clap(long)]
    remove_error: Option<PolkaBtcErrorCodeFromStr>,

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

async fn get_btc_rpc(
    wallet_name: String,
    bitcoin_opts: bitcoin::cli::BitcoinOpts,
    network: BitcoinNetwork,
) -> Result<BitcoinCore, Error> {
    let btc_rpc = BitcoinCore::new(bitcoin_opts.new_client(Some(&wallet_name))?, network.0);
    btc_rpc.create_wallet(&wallet_name).await?;
    Ok(btc_rpc)
}

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let (key_pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;

    match opts.subcmd {
        SubCommand::SetExchangeRate(info) => {
            let rate = FixedU128::checked_from_rational(info.exchange_rate, 100_000).unwrap();
            provider.set_exchange_rate_info(rate).await?;
        }
        SubCommand::GetExchangeRate => {
            let (rate, time, delay) = provider.get_exchange_rate_info().await?;
            println!(
                "Exchange Rate BTC/DOT: {:?}, Last Update: {}, Delay: {}",
                rate, time, delay
            );
        }
        SubCommand::SetBtcTxFees(info) => {
            provider
                .set_btc_tx_fees_per_byte(info.fast, info.half, info.hour)
                .await?;
        }
        SubCommand::GetBtcTxFees => {
            let fees = provider.get_btc_tx_fees_per_byte().await?;
            println!(
                "Fees per byte: fast={} half={} hour={}",
                fees.fast, fees.half, fees.hour
            );
        }
        SubCommand::GetCurrentTime => {
            println!("{}", provider.get_time_now().await?);
        }
        SubCommand::RegisterVault(info) => {
            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            vault::register_vault(
                provider,
                btc_rpc.get_new_public_key().await?,
                info.collateral,
            )
            .await?;
        }
        SubCommand::RequestIssue(info) => {
            let vault_id = info.vault.to_account_id();

            let griefing_collateral = match info.griefing_collateral {
                Some(x) => x,
                None => {
                    // calculate required amount
                    let amount_in_dot = provider.btc_to_dots(info.issue_amount).await?;
                    let required_griefing_collateral_rate =
                        provider.get_issue_griefing_collateral().await?;

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
                    info!(
                        "Griefing collateral not set; defaulting to {}",
                        griefing_collateral
                    );
                    griefing_collateral
                }
            };

            let request_data =
                issue::request_issue(&provider, info.issue_amount, griefing_collateral, vault_id)
                    .await?;

            let vault_btc_address = request_data.btc_address;

            if info.no_execute {
                println!("{}", hex::encode(request_data.issue_id.as_bytes()));
                return Ok(());
            }

            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            issue::execute_issue(
                &provider,
                &btc_rpc,
                request_data.issue_id,
                request_data.amount,
                vault_btc_address,
            )
            .await?;
        }
        SubCommand::SendBitcoin(info) => {
            let (btc_address, satoshis) = if let Some(issue_id) = info.issue_id {
                // gets the data from on-chain
                let issue_request = issue::get_issue_by_id(&provider, issue_id).await?;
                if issue_request.completed {
                    return Err(Error::IssueCompleted);
                } else if issue_request.cancelled {
                    return Err(Error::IssueCancelled);
                }

                (
                    issue_request.btc_address,
                    issue_request.amount + issue_request.fee,
                )
            } else {
                // expects cli configuration
                let btc_address = info.btc_address.ok_or(Error::ExpectedBitcoinAddress)?.0;
                (btc_address, info.satoshis)
            };

            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            let tx_metadata = btc_rpc
                .send_to_address(
                    btc_address,
                    satoshis.try_into().unwrap(),
                    None,
                    Duration::from_secs(15 * 60),
                    1,
                )
                .await?;

            println!("{}", tx_metadata.txid);
        }
        SubCommand::RequestRedeem(info) => {
            let redeem_id = redeem::request_redeem(
                &provider,
                info.redeem_amount,
                info.btc_address.0,
                info.vault.to_account_id(),
            )
            .await?;
            println!("{}", hex::encode(redeem_id.as_bytes()));
        }
        SubCommand::ExecuteRedeem(info) => {
            let redeem_id = info.redeem_id;
            let redeem_request = provider.get_redeem_request(redeem_id).await?;

            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            redeem::execute_redeem(
                &provider,
                &btc_rpc,
                redeem_id,
                redeem_request.amount_btc,
                redeem_request.btc_address,
            )
            .await?;
        }
        SubCommand::RequestReplace(info) => {
            let replace_id =
                replace::request_replace(&provider, info.replace_amount, info.griefing_collateral)
                    .await?;
            println!("{}", hex::encode(replace_id.as_bytes()));
        }
        SubCommand::AcceptReplace(info) => {
            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            replace::accept_replace(&provider, &btc_rpc, info.replace_id, info.collateral).await?;
        }
        SubCommand::ExecuteReplace(info) => {
            let btc_rpc = get_btc_rpc(wallet_name, opts.bitcoin, info.bitcoin_network).await?;
            replace::execute_replace(&provider, &btc_rpc, info.replace_id).await?;
        }
        SubCommand::GetChainStats(opts) => {
            stats::report_chain_stats(&provider, opts.start, opts.end).await?;
        }
        SubCommand::DumpEvents(opts) => {
            if opts.raw {
                stats::dump_raw_events(&provider).await?;
            } else {
                stats::dump_json(&provider, &opts.output_folder).await?;
            }
        }
        SubCommand::ApiCall(api_call) => match api_call.subcmd {
            ApiSubCommand::Vault(cmd) => match cmd.subcmd {
                VaultApiSubCommand::RegisterVault(info) => {
                    api::call::<_, ()>(cmd.url, "register_vault", info).await?;
                }
                VaultApiSubCommand::LockAdditionalCollateral(info) => {
                    api::call::<_, ()>(cmd.url, "lock_additional_collateral", info).await?;
                }
                VaultApiSubCommand::WithdrawCollateral(info) => {
                    api::call::<_, ()>(cmd.url, "withdraw_collateral", info).await?;
                }
                VaultApiSubCommand::RequestReplace(info) => {
                    api::call::<_, ()>(cmd.url, "request_replace", info).await?;
                }
                VaultApiSubCommand::UpdateBtcAddress(info) => {
                    api::call::<_, ()>(cmd.url, "update_btc_address", info).await?;
                }
                VaultApiSubCommand::WithdrawReplace(info) => {
                    api::call::<_, ()>(cmd.url, "withdraw_replace", info).await?;
                }
            },
            ApiSubCommand::Relayer(cmd) => match cmd.subcmd {
                RelayerApiSubCommand::SuggestStatusUpdate(info) => {
                    api::call::<_, ()>(cmd.url, "suggest_status_update", info).await?;
                }
                RelayerApiSubCommand::VoteOnStatusUpdate(info) => {
                    api::call::<_, ()>(cmd.url, "vote_on_status_update", info).await?;
                }
                RelayerApiSubCommand::Register(info) => {
                    api::call::<_, ()>(cmd.url, "register_staked_relayer", info).await?;
                }
                RelayerApiSubCommand::Deregister => {
                    api::call::<_, ()>(cmd.url, "deregister_staked_relayer", ()).await?;
                }
                RelayerApiSubCommand::SystemHealth => {
                    api::call::<_, ()>(cmd.url, "system_health", ()).await?;
                }
                RelayerApiSubCommand::AccountId => {
                    let ret = api::call::<_, String>(cmd.url, "account_id", ()).await?;
                    println!("{}", ret);
                }
            },
        },
        SubCommand::SetIssuePeriod(info) => {
            issue::set_issue_period(&provider, info.period).await?;
        }
        SubCommand::SetRedeemPeriod(info) => {
            redeem::set_redeem_period(&provider, info.period).await?;
        }
        SubCommand::SetReplacePeriod(info) => {
            replace::set_replace_period(&provider, info.period).await?;
        }
        SubCommand::SetRelayerMaturityPeriod(info) => {
            provider.set_maturity_period(info.period).await?;
        }
    }

    Ok(())
}
