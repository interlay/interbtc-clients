mod bitcoin;
mod env;
mod error;
mod grpc;
mod poll;
mod relay;
mod rpc;

use error::Error;
use futures::stream::{FuturesUnordered, StreamExt};
use grpc::{Service, StakedRelayerServer};
use log::{error, info};
use relay::Client as PolkaClient;
use relayer_core::{Config, Runner};
use rpc::Provider;
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
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
    let register_prov = api_prov.clone();
    let other_prov = api_prov.clone();

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

    let vaults = other_prov
        .get_all_vaults()
        .await?
        .into_iter()
        .map(|vault| (vault.btc_address, vault));

    let all_vaults = vaults.clone();

    let vaults_rw: Arc<RwLock<HashMap<_, _>>> = Arc::new(RwLock::new(vaults.into_iter().collect()));
    let vaults_ro = vaults_rw.clone();
    println!("vaults: {:?}", vaults_rw);

    let mut workers = FuturesUnordered::new();

    for vault in all_vaults {
        workers.push(async {
            poll::check_until_true(Duration::from_secs(3), || async { return (true, 100u32) }).await
        });
    }

    // let verifier = rpc::OracleChecker { rpc: other_prov };

    let mut btc_height = 1834437;
    let btc_rpc = bitcoin::BitcoinMonitor::from_env()?;

    let result = tokio::try_join!(
        // runs grpc server for incoming requests
        tokio::spawn(async move { router.serve(addr).await.unwrap() }),
        // runs subscription service to update registered vaults
        tokio::spawn(async move {
            register_prov
                .on_register(|vault| {
                    info!("Vault registered: {}", vault.id);
                    vaults_rw.write().unwrap().insert(vault.btc_address, vault);
                })
                .await
                .unwrap()
        }),
        // runs oracle liveness check
        // tokio::spawn(async move {
        //     poll::check_until_true(std::time::Duration::from_secs(5), || async {
        //         match verifier.is_oracle_offline().await {
        //             Ok(is_offline) => {
        //                 if is_offline {
        //                     // TODO: report
        //                     info!("Oracle is offline, reporting...");
        //                 }
        //             }
        //             Err(e) => error!("Liveness check failed: {}", e.to_string()),
        //         }
        //     })
        //     .await
        // }),
        // runs vault liquidation checks
        tokio::spawn(async move {
            poll::run_all(workers, |vault| async {
                println!("hello");
            })
            .await
        }),
        // runs vault theft checks
        tokio::spawn(async move {
            loop {
                let hash = btc_rpc.wait_for_block(btc_height).await.unwrap();
                for maybe_tx in btc_rpc.get_block_transactions(hash).unwrap() {
                    if let Some(tx) = maybe_tx {
                        // filter matching vaults
                        let addrs = bitcoin::extract_btc_addresses(tx)
                            .into_iter()
                            .filter(|addr| vaults_ro.read().unwrap().contains_key(addr))
                            .collect::<Vec<_>>();
                        if addrs.len() > 0 {
                            println!("{:?}", addrs);
                        }

                        // check if matching redeem or replace request

                        // report vault theft
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
