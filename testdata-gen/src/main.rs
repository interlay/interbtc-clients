mod btc_relay;
mod error;
mod issue;
mod redeem;
mod replace;
mod utils;
mod vault;

use bitcoin::{BitcoinCore, ConversionError};
use clap::Clap;
use error::Error;
use runtime::{
    substrate_subxt::PairSigner, ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime,
    RedeemPallet, TimestampPallet,
};
use sp_core::{H160, H256};
use sp_keyring::AccountKeyring;
use std::str::FromStr;

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
    }

    Ok(())
}
