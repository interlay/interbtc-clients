mod bitcoin;
mod error;
mod grpc;
mod relay;
mod rpc;
mod utils;

use clap::Clap;
use error::Error;
use grpc::{Service, StakedRelayerServer};
use log::{error, info};
use relay::Client as PolkaClient;
use relay::Error as RelayError;
use relayer_core::bitcoin::Client as BtcClient;
use relayer_core::{Backing, Config, Runner};
use rpc::{OracleChecker, Provider};
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use substrate_subxt::{ClientBuilder, PairSigner};
use tokio::sync::Mutex;
use tonic::transport::Server;

/// The Staked Relayer client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    #[clap(long, default_value = "[::1]:50051")]
    grpc_addr: String,

    #[clap(long)]
    scan_height: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let provider = Provider::new(client, Arc::new(Mutex::new(signer)));
    let shared_prov = Arc::new(provider);

    let addr = opts.grpc_addr.parse().unwrap();
    let service = Service::new(shared_prov.clone());
    let router = Server::builder().add_service(StakedRelayerServer::new(service));

    let btc_client = BtcClient::new::<RelayError>(bitcoin::bitcoin_rpc_from_env()?);

    let mut btc_height = if let Some(height) = opts.scan_height {
        height
    } else {
        btc_client.get_block_count()? + 1
    };
    let btc_rpc = bitcoin::BitcoinMonitor::new(bitcoin::bitcoin_rpc_from_env()?);

    let mut runner = Runner::new(
        PolkaClient::new(shared_prov.clone()),
        btc_client,
        Config {
            // TODO: pass config
            start_height: 1831944,
            max_batch_size: 1,
        },
    )?;

    let vault_prov = shared_prov.clone();
    let vaults = vault_prov
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.btc_address, vault));

    let vaults_rw: Arc<RwLock<HashMap<_, _>>> = Arc::new(RwLock::new(vaults.into_iter().collect()));
    let vaults_ro = vaults_rw.clone();

    let tx_provider = shared_prov.clone();

    let result = tokio::try_join!(
        // runs grpc server for incoming requests
        tokio::spawn(async move { router.serve(addr).await.unwrap() }),
        // runs subscription service to update registered vaults
        tokio::spawn(async move {
            vault_prov
                .on_register(|vault| {
                    info!("Vault registered: {}", vault.id);
                    vaults_rw.write().unwrap().insert(vault.btc_address, vault);
                })
                .await
                .unwrap()
        }),
        // runs oracle liveness check
        tokio::spawn(async move {
            let verifier = OracleChecker::new(shared_prov.clone());

            utils::check_every(std::time::Duration::from_secs(5), || async {
                match verifier.is_oracle_offline().await {
                    Ok(is_offline) => {
                        if is_offline {
                            info!("Oracle is offline, reporting...");
                            // TODO: report oracle offline
                        }
                    }
                    Err(e) => error!("Liveness check failed: {}", e.to_string()),
                }
            })
            .await
        }),
        // runs vault theft checks
        tokio::spawn(async move {
            loop {
                info!("Scanning height {}", btc_height);
                let hash = btc_rpc.wait_for_block(btc_height).await.unwrap();
                for maybe_tx in btc_rpc.get_block_transactions(hash).unwrap() {
                    if let Some(tx) = maybe_tx {
                        // filter matching vaults
                        let vault_ids = bitcoin::extract_btc_addresses(tx)
                            .into_iter()
                            .filter_map(|addr| {
                                let vaults = vaults_ro.read().unwrap();
                                if let Some(vault) = vaults.get(&addr) {
                                    return Some(vault.id.clone());
                                }
                                None
                            })
                            .collect::<Vec<_>>();

                        for vault_id in vault_ids {
                            info!("Found tx from vault {}", vault_id);
                            // check if matching redeem or replace request
                            if tx_provider
                                .is_transaction_invalid(vault_id, vec![])
                                .await
                                .unwrap()
                            {
                                info!("Transaction is invalid, reporting...");
                                // TODO: report vault theft
                            }
                        }
                    }
                }
                btc_height += 1;
            }
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
