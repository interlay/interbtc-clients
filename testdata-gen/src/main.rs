mod btc_relay;
mod error;
mod issue;
mod redeem;
mod vault;

use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use error::Error;
use runtime::{
    substrate_subxt::PairSigner, ExchangeRateOraclePallet, H256Le, PolkaBtcProvider,
    PolkaBtcRuntime, RedeemPallet, TimestampPallet,
};
use sp_core::H256;
use sp_keyring::AccountKeyring;
use std::convert::TryInto;
use std::str::FromStr;
use std::time::Duration;

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

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Set the DOT to BTC exchange rate.
    SetExchangeRate(ExchangeRateOracleInfo),
    /// Get the current DOT to BTC exchange rate.
    GetExchangeRate,
    /// Get the time as reported by the chain.
    GetCurrentTime,
    /// Register a new vault using the global keyring.
    RegisterVault(VaultRegistryInfo),
    /// Request issuance of PolkaBTC and transfer to vault.
    RequestIssue(IssueRequestInfo),
    /// Request that PolkaBTC be burned to redeem BTC.
    RequestRedeem(RedeemRequestInfo),
    /// Send BTC to user, must be called by vault.
    ExecuteRedeem(RedeemExecuteInfo),
}

#[derive(Clap)]
struct ExchangeRateOracleInfo {
    /// Exchange rate from BTC to DOT.
    #[clap(long, default_value = "1")]
    exchange_rate: u128,
}

#[derive(Clap)]
struct VaultRegistryInfo {
    /// Bitcoin address for vault to receive funds.
    #[clap(long)]
    btc_address: String,

    /// Collateral to secure position.
    #[clap(long, default_value = "0")]
    collateral: u128,
}

#[derive(Clap)]
struct IssueRequestInfo {
    /// Amount of PolkaBTC to issue.
    #[clap(long, default_value = "100000")]
    issue_amount: u128,

    /// Griefing collateral for request.
    #[clap(long, default_value = "100")]
    griefing_collateral: u128,

    /// Vault keyring to derive `vault_id`.
    #[clap(long, default_value = "bob")]
    vault: AccountKeyring,
}

#[derive(Clap)]
struct RedeemRequestInfo {
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
struct RedeemExecuteInfo {
    /// Redeem id for the redeem request.
    #[clap(long)]
    redeem_id: String,
}

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    let opts: Opts = Opts::parse();

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;

    let btc_rpc = BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?);

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
            // TODO: configure network
            let vault_btc_address =
                bitcoin::hash_to_p2wpkh(vault.wallet.get_btc_address(), bitcoin::Network::Regtest)?;

            let issue_id = issue::request_issue(
                &provider,
                info.issue_amount,
                info.griefing_collateral,
                vault_id,
            )
            .await?;

            let tx_metadata = btc_rpc
                .send_to_address(
                    vault_btc_address,
                    info.issue_amount.try_into().unwrap(),
                    &issue_id.to_fixed_bytes(),
                    Duration::from_secs(15 * 60),
                    1,
                )
                .await?;

            issue::execute_issue(
                &provider,
                &issue_id,
                &H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
                &tx_metadata.block_height,
                &tx_metadata.proof,
                &tx_metadata.raw_tx,
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
            println!("{}", redeem_id);
        }
        SubCommand::ExecuteRedeem(info) => {
            let redeem_id = H256::from_str(&info.redeem_id).map_err(|_| Error::InvalidRequestId)?;
            let redeem_request = provider.get_redeem_request(redeem_id).await?;

            // TODO: configure network
            let btc_address =
                bitcoin::hash_to_p2wpkh(redeem_request.btc_address, bitcoin::Network::Regtest)?;

            let tx_metadata = btc_rpc
                .send_to_address(
                    btc_address,
                    redeem_request.amount_btc.try_into().unwrap(),
                    &redeem_id.to_fixed_bytes(),
                    Duration::from_secs(15 * 60),
                    1,
                )
                .await?;

            redeem::execute_redeem(
                provider,
                &redeem_id,
                &H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
                &tx_metadata.block_height,
                &tx_metadata.proof,
                &tx_metadata.raw_tx,
            )
            .await?;
        }
    }

    Ok(())
}
