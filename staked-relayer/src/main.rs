mod bitcoin;
mod env;
mod error;
mod grpc;
mod poll;
mod relay;
mod rpc;

use error::Error;
use grpc::{Service, StakedRelayerServer};
use log::{error, info};
use relay::Client as PolkaClient;
use relayer_core::{Config, Runner};
use rpc::Provider;
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use substrate_subxt::{ClientBuilder, PairSigner};
use tokio::sync::Mutex;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let api_prov = Provider::new(client, Arc::new(Mutex::new(signer)));
    let relay_prov = api_prov.clone();
    let vault_prov = api_prov.clone();
    let oracle_prov = api_prov.clone();
    let tx_prov = api_prov.clone();

    let addr = "[::1]:50051".parse().unwrap();
    let service = Service { rpc: api_prov };
    let router = Server::builder().add_service(StakedRelayerServer::new(service));

    let btc_client = env::bitcoin_from_env()?;
    let polka_client = PolkaClient::new(relay_prov)?;

    let mut runner = Runner::new(
        polka_client,
        btc_client,
        Config {
            // TODO: pass config
            start_height: 1831944,
            max_batch_size: 1,
        },
    )?;

    let vaults = vault_prov
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.btc_address, vault));
    println!("Vaults: {:?}", vaults);

    let vaults_rw: Arc<RwLock<HashMap<_, _>>> = Arc::new(RwLock::new(vaults.into_iter().collect()));
    let vaults_ro = vaults_rw.clone();

    let mut btc_height = 1834437;
    let btc_rpc = bitcoin::BitcoinMonitor::from_env()?;

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
            let verifier = rpc::OracleChecker { rpc: oracle_prov };

            poll::check_every(std::time::Duration::from_secs(5), || async {
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
                            if tx_prov
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
        }) // tokio::task::spawn_blocking(move || runner.run().unwrap())
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
