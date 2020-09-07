mod env;
mod error;
mod http;
mod relay;
mod rpc;

use error::Error;
use relay::Client as PolkaClient;
use relayer_core::{Config, Runner};
use rpc::Provider;
use runtime::PolkaBTC;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use substrate_subxt::{ClientBuilder, PairSigner};

pub fn start_relay(rpc: Provider) -> Result<(), Error> {
    let btc_client = env::bitcoin_from_env()?;
    let polka_client = PolkaClient::new(rpc)?;

    let mut runner = Runner::new(
        polka_client,
        btc_client,
        Config {
            // TODO: pass config
            start_height: 1831944,
            max_batch_size: 1,
        },
    )?;
    runner.run()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();

    let client = ClientBuilder::<PolkaBTC>::new().build().await?;
    let signer = PairSigner::<PolkaBTC, _>::new(AccountKeyring::Alice.pair());
    let api_prov = rpc::Provider::new(client, Arc::new(signer));
    let relay_prov = api_prov.clone();

    let btc = tokio::task::spawn_blocking(move || start_relay(relay_prov));
    let api = tokio::spawn(async move { http::start(api_prov).await });

    let result = tokio::try_join!(api, btc);
    match result {
        Ok(_) => (),
        Err(err) => {
            println!("Error: {}", err);
        }
    };
    Ok(())
}
