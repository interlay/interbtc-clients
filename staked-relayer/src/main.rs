mod bitcoin;
mod error;
mod http;
mod oracle;
mod relay;
mod utils;
mod vault;

use bitcoin::{BlockHash, Hash};
use clap::Clap;
use error::Error;
use log::{error, info};
use oracle::Oracle;
use relay::Client as PolkaClient;
use relay::Error as RelayError;
use relayer_core::bitcoin::Client as BtcClient;
use relayer_core::{Backing, Config, Runner};
use runtime::{
    ErrorCode, H256Le, PolkaBtcProvider, PolkaBtcRuntime, StakedRelayerPallet, StatusCode,
};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::PairSigner;
use tokio::sync::RwLock;

use vault::{Vaults, VaultsWatcher};

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Address to listen on for JSON-RPC requests.
    #[clap(long, default_value = "[::1]:3030")]
    http_addr: String,

    /// Starting height for vault theft checks, if not defined
    /// automatically start from the chain tip.
    #[clap(long)]
    scan_start_height: Option<u32>,

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
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let oracle_timeout_ms = opts.oracle_timeout_ms;
    let status_update_deposit = opts.status_update_deposit;

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let provider =
        PolkaBtcProvider::from_url(opts.polka_btc_url, Arc::new(RwLock::new(signer))).await?;
    let shared_prov = Arc::new(provider);

    let api_prov = shared_prov.clone();
    let btc_client = BtcClient::new::<RelayError>(bitcoin::bitcoin_rpc_from_env()?);

    // scan from custom height or the current tip
    let btc_height = if let Some(height) = opts.scan_start_height {
        height
    } else {
        btc_client.get_block_count()? + 1
    };
    let btc_rpc = Arc::new(bitcoin::BitcoinMonitor::new(
        bitcoin::bitcoin_rpc_from_env()?
    ));
    let vault_btc_rpc = btc_rpc.clone();
    let block_btc_rpc = btc_rpc.clone();
    let status_btc_rpc = btc_rpc.clone();

    let mut runner = Runner::new(
        PolkaClient::new(shared_prov.clone()),
        btc_client,
        Config {
            start_height: opts.relay_start_height.unwrap_or(0),
            max_batch_size: opts.max_batch_size,
        },
    )?;

    let block_prov = shared_prov.clone();
    let suggest_prov = shared_prov.clone();
    let update_prov = shared_prov.clone();

    let vault_prov = shared_prov.clone();
    let vaults = vault_prov
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.btc_address, vault));

    // collect (btc_address, vault) into HashMap
    let vaults_arc = Arc::new(Vaults::from(vaults.into_iter().collect()));
    let vaults_rw = vaults_arc.clone();
    let vaults_ro = vaults_arc.clone();

    let mut vaults_watcher =
        VaultsWatcher::new(btc_height, vault_btc_rpc, vaults_ro, vault_prov.clone());

    let http_addr = opts.http_addr.parse()?;

    let result = tokio::try_join!(
        // runs grpc server for incoming requests
        tokio::spawn(async move { http::start(api_prov, http_addr).await }),
        // runs subscription service to update registered vaults
        tokio::spawn(async move {
            vault_prov
                .on_register(
                    |vault| async {
                        info!("Vault registered: {}", vault.id);
                        vaults_rw.write(vault.btc_address, vault).await;
                    },
                    |err| error!("{}", err.to_string()),
                )
                .await
                .unwrap()
        }),
        // runs oracle liveness check
        tokio::spawn(async move {
            let oracle = Oracle::new(shared_prov.clone());
            utils::check_every(Duration::from_millis(oracle_timeout_ms), || async {
                oracle.report_offline().await
            })
            .await
        }),
        // runs vault theft checks
        tokio::spawn(async move {
            vaults_watcher.watch().await;
        }),
        // runs `NO_DATA` checks and submits status update
        tokio::spawn(async move {
            let block_btc_rpc = &block_btc_rpc;
            let suggest_prov = &suggest_prov;
            block_prov
                .on_store_block(
                    |height, hash| async move {
                        // TODO: check if user submitted
                        info!("Block submission: {}", hash);
                        match block_btc_rpc.get_block_hash(height) {
                            Ok(_) => info!("Block exists"),
                            Err(_) => {
                                if let Err(e) = suggest_prov
                                    .suggest_status_update(
                                        status_update_deposit,
                                        StatusCode::Error,
                                        Some(ErrorCode::NoDataBTCRelay),
                                        None,
                                        Some(hash),
                                    )
                                    .await
                                {
                                    error!("Failed to report block NO_DATA: {}", e.to_string());
                                }
                            }
                        }
                    },
                    |err| error!("Error receiving store block event: {}", err.to_string()),
                )
                .await
                .unwrap()
        }),
        // runs subscription service for suggested status updates
        tokio::spawn(async move {
            let status_btc_rpc = &status_btc_rpc;
            let update_prov = &update_prov;
            update_prov
                .on_status_update_suggested(
                    |event| async move {
                        info!("Status update {} suggested", event.status_update_id);

                        // TODO: ignore self submitted

                        // we can only automate NO_DATA checks, all other suggestible
                        // status updates can only be voted upon manually
                        if let Some(ErrorCode::NoDataBTCRelay) = event.add_error {
                            match status_btc_rpc
                                .is_block_known(convert_block_hash(event.block_hash).unwrap())
                            {
                                Ok(true) => {
                                    update_prov
                                        .vote_on_status_update(event.status_update_id, false)
                                        .await;
                                }
                                Ok(false) => {
                                    update_prov
                                        .vote_on_status_update(event.status_update_id, true)
                                        .await;
                                }
                                Err(err) => error!("Error validating block: {}", err.to_string()),
                            }
                        }
                    },
                    |err| error!("Error receiving status update: {}", err.to_string()),
                )
                .await
                .unwrap()
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

fn convert_block_hash(hash: Option<H256Le>) -> Result<BlockHash, Error> {
    if let Some(hash) = hash {
        return BlockHash::from_slice(&hash.to_bytes_le()).map_err(|_| Error::InvalidBlockHash);
    }
    Err(Error::EventNoBlockHash)
}
