use relayer_core::{Config, Runner};
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::{ClientBuilder, PairSigner};

mod client;
mod env;
mod error;
mod http;
mod rpc;

use client::Client as PolkadotClient;

use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let provider = rpc::Provider::new(client, Arc::new(signer));

    let btc_client = env::bitcoin_from_env().unwrap();
    let polka_client = PolkadotClient::new(provider).unwrap();

    let mut runner = Runner::new(
        polka_client,
        btc_client,
        Config {
            start_height: 1831396,
            use_best_height: false,
            max_batch_size: 10,
            initialize: true,
        },
    )
    .unwrap();
    runner.run().unwrap();

    // http::start(provider).await;

    // let listen = node.on_proposal();

    // // node.register_staked_relayer(100).await?;
    // node.suggest_status_update(100, StatusCode::Shutdown)
    //     .join(listen)
    //     .await;

    // node.deregister_staked_relayer().await?;
    // println!("{:?}", result);
    Ok(())
}
