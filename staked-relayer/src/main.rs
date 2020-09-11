mod env;
mod error;
mod grpc;
mod poll;
mod relay;
mod rpc;

use error::Error;
use grpc::{Service, StakedRelayerServer};
use log::info;
use relay::Client as PolkaClient;
use relayer_core::{Config, Runner};
use rpc::Provider;
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::{ClientBuilder, PairSigner};
use tokio::sync::Mutex;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let api_prov = rpc::Provider::new(client, Arc::new(Mutex::new(signer)));
    let relay_prov = api_prov.clone();
    let status_prov = api_prov.clone();
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

    let verifier = rpc::Verifier { rpc: other_prov };

    let result = tokio::try_join!(
        tokio::spawn(async move { router.serve(addr).await }),
        tokio::spawn(async move {
            status_prov
                .on_proposal(|id, _code, _add, _remove| {
                    info!("Status Update: {}", id);
                    // TODO: verify & vote
                })
                .await
        }),
        tokio::spawn(async move {
            poll::check_status(std::time::Duration::from_secs(5), || async {
                verifier.is_oracle_offline().await
            })
            .await
        }),
        tokio::task::spawn_blocking(move || runner.run())
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
