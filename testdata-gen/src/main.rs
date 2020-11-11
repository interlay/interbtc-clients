mod api;
mod btc_relay;
mod error;
mod issue;
mod redeem;
mod replace;
mod utils;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi, ConversionError};
use clap::Clap;
use error::Error;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    substrate_subxt::PairSigner, ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime,
    RedeemPallet, TimestampPallet, VaultRegistryPallet,
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
}

#[derive(Clap)]
struct ApiCall {
    /// API URL.
    #[clap(long, default_value = "http://127.0.0.1:3031")]
    url: String,

    #[clap(subcommand)]
    subcmd: ApiSubCommand,
}
#[derive(Clap)]
enum ApiSubCommand {
    RequestReplace(RequestReplaceJsonRpcRequest),
    RegisterVault(RegisterVaultJsonRpcRequest),
    LockAdditionalCollateral(LockAdditionalCollateralJsonRpcRequest),
    WithdrawCollateral(WithdrawCollateralJsonRpcRequest),
    UpdateBtcAddress(UpdateBtcAddressJsonRpcRequest),
    WithdrawReplace(WithdrawReplaceJsonRpcRequest),
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
struct SetExchangeRateInfo {
    /// Exchange rate from BTC to DOT.
    #[clap(long, default_value = "1")]
    exchange_rate: u128,
}

#[derive(Clap)]
struct RegisterVaultInfo {
    /// Bitcoin address for vault to receive funds.
    #[clap(long)]
    btc_address: String,

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
    btc_address: String,

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

    let btc_rpc = BitcoinCore::new(opts.bitcoin.new_client()?);

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
        SubCommand::GetCurrentTime => {
            println!("{}", provider.get_time_now().await?);
        }
        SubCommand::RegisterVault(info) => {
            vault::register_vault(provider, &info.btc_address, info.collateral).await?;
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
                &info.btc_address,
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
        SubCommand::ApiCall(api_call) => {
            let url = api_call.url;
            match api_call.subcmd {
                ApiSubCommand::RegisterVault(info) => {
                    api::call(url, "register_vault", info).await?;
                }
                ApiSubCommand::LockAdditionalCollateral(info) => {
                    api::call(url, "lock_additional_collateral", info).await?;
                }
                ApiSubCommand::WithdrawCollateral(info) => {
                    api::call(url, "withdraw_collateral", info).await?;
                }
                ApiSubCommand::RequestReplace(info) => {
                    api::call(url, "request_replace", info).await?;
                }
                ApiSubCommand::UpdateBtcAddress(info) => {
                    api::call(url, "update_btc_address", info).await?;
                }
                ApiSubCommand::WithdrawReplace(info) => {
                    api::call(url, "withdraw_replace", info).await?;
                }
            }
        }
    }

    Ok(())
}
