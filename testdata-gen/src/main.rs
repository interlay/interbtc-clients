use sp_keyring::AccountKeyring;
use substrate_subxt::PairSigner;
use runtime::{ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime, Error};
use tokio::sync::Mutex;
use std::sync::Arc;

const POLKA_BTC_URL: &str = "ws://127.0.0.1:9944";

/// Generates testdata to be used on a development environment of the BTC-Parachain
#[tokio::main]
async fn main() -> Result<(), Error> {
    // setup BTC Parachain connection
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(AccountKeyring::Alice.pair());
    let provider = PolkaBtcProvider::new(POLKA_BTC_URL.to_string(), Arc::new(Mutex::new(signer))).await?;
    let shared_prov = Arc::new(provider);


    let oracle_prov = shared_prov.clone();

    let (rate, time, delay) = oracle_prov.get_exchange_rate_info().await?;
    println!("{:?}", rate);

    Ok(())
}
