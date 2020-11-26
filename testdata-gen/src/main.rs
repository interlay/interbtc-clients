mod api;
mod btc_relay;
mod error;
mod issue;
mod redeem;
mod replace;
mod stats;
mod utils;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi, ConversionError};
use clap::Clap;
use error::Error;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    substrate_subxt::PairSigner, ErrorCode as PolkaBtcErrorCode, ExchangeRateOraclePallet, H256Le,
    PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet, StatusCode as PolkaBtcStatusCode,
    TimestampPallet, VaultRegistryPallet,
};
use sp_core::{H160, H256};
use sp_keyring::AccountKeyring;
use std::array::TryFromSliceError;
use std::convert::TryInto;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Encode, Decode)]
struct H160FromStr(H160);
impl std::str::FromStr for H160FromStr {
    type Err = ConversionError;
    fn from_str(btc_address: &str) -> Result<Self, Self::Err> {
        Ok(H160FromStr(bitcoin::get_hash_from_string(btc_address)?))
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

    /// Keyring used to sign transactions.
    #[clap(long, default_value = "alice")]
    keyring: AccountKeyring,

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

enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl FromStr for BitcoinNetwork {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(Error::UnknownBitcoinNetwork),
        }
    }
}

impl BitcoinNetwork {
    fn hash_to_addr(&self, hash: H160) -> Result<String, ConversionError> {
        match *self {
            BitcoinNetwork::Mainnet => bitcoin::hash_to_p2wpkh(hash, bitcoin::Network::Bitcoin),
            BitcoinNetwork::Testnet => bitcoin::hash_to_p2wpkh(hash, bitcoin::Network::Testnet),
            BitcoinNetwork::Regtest => bitcoin::hash_to_p2wpkh(hash, bitcoin::Network::Regtest),
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
    /// Bitcoin address for vault to receive funds.
    #[clap(long)]
    btc_address: H160FromStr,

    /// Collateral to secure position.
    #[clap(long, default_value = "100000")]
    collateral: u128,
}

#[derive(Clap)]
struct RequestIssueInfo {
    /// Amount of PolkaBTC to issue.
    #[clap(long, default_value = "100000")]
    issue_amount: u128,

    /// Griefing collateral for request.
    #[clap(long, default_value = "100")]
    griefing_collateral: u128,

    /// Vault keyring to derive `vault_id`.
    #[clap(long, default_value = "bob")]
    vault: AccountKeyring,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    bitcoin_network: BitcoinNetwork,
}

#[derive(Clap)]
struct SendBitcoinInfo {
    /// Recipient Bitcoin address.
    #[clap(long)]
    btc_address: String,

    /// Amount of BTC to transfer.
    #[clap(long, default_value = "0")]
    satoshis: u64,

    /// Hex encoded OP_RETURN data for request.
    #[clap(long)]
    op_return: String,
}

#[derive(Clap)]
struct RequestRedeemInfo {
    /// Amount of PolkaBTC to redeem.
    #[clap(long, default_value = "500")]
    redeem_amount: u128,

    /// Bitcoin address for vault to send funds.
    #[clap(long)]
    btc_address: H160FromStr,

    /// Vault keyring to derive `vault_id`.
    #[clap(long, default_value = "bob")]
    vault: AccountKeyring,
}

#[derive(Clap)]
struct ExecuteRedeemInfo {
    /// Redeem id for the redeem request.
    #[clap(long)]
    redeem_id: String,

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
    replace_id: String,

    /// Collateral used to back replace.
    #[clap(long, default_value = "10000")]
    collateral: u128,
}

#[derive(Clap)]
struct ExecuteReplaceInfo {
    /// Replace id for the replace request.
    #[clap(long)]
    replace_id: String,
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
    btc_address: H160FromStr,
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
    address: H160FromStr,
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

fn data_to_request_id(data: &[u8]) -> Result<[u8; 32], TryFromSliceError> {
    data.try_into()
}

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;

    let btc_rpc = BitcoinCore::new(opts.bitcoin.new_client(Some(&format!("{}", opts.keyring)))?);

    match opts.subcmd {
        SubCommand::SetExchangeRate(info) => {
            provider.set_exchange_rate_info(info.exchange_rate).await?;
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
            vault::register_vault(provider, info.btc_address.0, info.collateral).await?;
        }
        SubCommand::RequestIssue(info) => {
            let vault_id = info.vault.to_account_id();
            let vault = provider.get_vault(vault_id.clone()).await?;

            let vault_btc_address = info
                .bitcoin_network
                .hash_to_addr(vault.wallet.get_btc_address())?;

            let issue_id = issue::request_issue(
                &provider,
                info.issue_amount,
                info.griefing_collateral,
                vault_id,
            )
            .await?;

            issue::execute_issue(
                &provider,
                &btc_rpc,
                issue_id,
                info.issue_amount,
                vault_btc_address,
            )
            .await?;
        }
        SubCommand::SendBitcoin(info) => {
            let data = &hex::decode(info.op_return)?;

            let tx_metadata = btc_rpc
                .send_to_address(
                    info.btc_address,
                    info.satoshis,
                    &data_to_request_id(data)?,
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
            let redeem_id = H256::from_str(&info.redeem_id).map_err(|_| Error::InvalidRequestId)?;
            let redeem_request = provider.get_redeem_request(redeem_id).await?;

            let btc_address = info
                .bitcoin_network
                .hash_to_addr(redeem_request.btc_address)?;

            redeem::execute_redeem(
                &provider,
                &btc_rpc,
                redeem_id,
                redeem_request.amount_btc,
                btc_address,
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
            let replace_id =
                H256::from_str(&info.replace_id).map_err(|_| Error::InvalidRequestId)?;
            replace::accept_replace(&provider, replace_id, info.collateral).await?;
        }
        SubCommand::ExecuteReplace(info) => {
            let replace_id =
                H256::from_str(&info.replace_id).map_err(|_| Error::InvalidRequestId)?;
            replace::execute_replace(&provider, &btc_rpc, replace_id).await?;
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
    }

    Ok(())
}
