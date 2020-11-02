mod error;
mod http;
mod oracle;
mod relay;
mod status;
mod utils;
mod vault;

use clap::Clap;
use error::Error;
use oracle::OracleMonitor;
use relay::Client as PolkaClient;
use relay::Error as RelayError;
use relayer_core::bitcoin::Client as BtcClient;
use relayer_core::{Backing, Config, Runner};
use runtime::substrate_subxt::PairSigner;
use runtime::{PolkaBtcProvider, PolkaBtcRuntime};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;

use status::*;
use vault::*;

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::0]:3030")]
    http_addr: String,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    scan_start_height: Option<u32>,

    /// Delay for checking Bitcoin for new blocks (in seconds).
    #[clap(long, default_value = "60")]
    scan_block_delay: u64,

    /// Starting height to relay block headers, if not defined
    /// use the best height as reported by the relay module.
    #[clap(long)]
    relay_start_height: Option<u32>,

    /// Max batch size for combined block header submission,
    /// currently unsupported.
    #[clap(long, default_value = "1", possible_value = "1")]
    max_batch_size: u32,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "5000")]
    oracle_timeout_ms: u64,

    /// Timeout in milliseconds to repeat oracle liveness check.
    #[clap(long, default_value = "100")]
    status_update_deposit: u128,

    /// Comma separated list of allowed origins.
    #[clap(long, default_value = "*")]
    rpc_cors_domain: String,

    /// Staked relayer keyring.
    #[clap(long, default_value = "alice")]
    keyring: AccountKeyring,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let http_addr = opts.http_addr.parse()?;
    let oracle_timeout_ms = opts.oracle_timeout_ms;

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    let btc_client = BtcClient::new::<RelayError>(bitcoin::bitcoin_rpc_from_env()?);

    let current_height = btc_client.get_block_count()?;

    // scan from custom height or the current tip
    let btc_height = if let Some(height) = opts.scan_start_height {
        height
    } else {
        current_height + 1
    };
    let btc_rpc = Arc::new(bitcoin::BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));

    let mut runner = Runner::new(
        PolkaClient::new(provider.clone()),
        btc_client,
        Config {
            start_height: opts.relay_start_height.unwrap_or(current_height),
            max_batch_size: opts.max_batch_size,
        },
    )?;

    let oracle_monitor = OracleMonitor::new(provider.clone());

    let vaults = provider
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.wallet.get_btc_address(), vault));

    // collect (btc_address, vault) into HashMap
    let vaults = Arc::new(Vaults::from(vaults.into_iter().collect()));
    let mut vaults_monitor = VaultsMonitor::new(
        btc_height,
        btc_rpc.clone(),
        vaults.clone(),
        provider.clone(),
        Duration::from_secs(opts.scan_block_delay),
    );

    let vaults_listener = listen_for_vaults_registered(provider.clone(), vaults);
    let status_update_listener = listen_for_status_updates(btc_rpc.clone(), provider.clone());
    let relay_listener = listen_for_blocks_stored(
        btc_rpc.clone(),
        provider.clone(),
        opts.status_update_deposit,
    );

    let api = http::start(provider.clone(), http_addr, opts.rpc_cors_domain);

    let result = tokio::try_join!(
        // runs json-rpc server for incoming requests
        tokio::spawn(async move { api.await }),
        // runs subscription service to update registered vaults
        tokio::spawn(async move { vaults_listener.await.unwrap() }),
        // runs vault theft checks
        tokio::spawn(async move {
            vaults_monitor.scan().await;
        }),
        // runs oracle liveness check
        tokio::spawn(async move {
            utils::check_every(Duration::from_millis(oracle_timeout_ms), || async {
                oracle_monitor.report_offline().await
            })
            .await
        }),
        // runs `NO_DATA` checks and submits status updates
        tokio::spawn(async move {
            relay_listener.await.unwrap();
        }),
        // runs subscription service for status updates
        tokio::spawn(async move {
            status_update_listener.await.unwrap();
        }),
        tokio::task::spawn_blocking(move || runner.run().unwrap())
    );
    match result {
        Ok(res) => {
            println!("{:?}", res);
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };
    Ok(())
}
