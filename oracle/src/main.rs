use clap::Clap;
use log::{error, info};
use runtime::{Error, ExchangeRateOraclePallet, PolkaBtcProvider, PolkaBtcRuntime};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;
use runtime::substrate_subxt::PairSigner;
use tokio::time::delay_for;

/// Simple oracle liveness service to automatically update the
/// exchange rate periodically.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Exchange rate from BTC to DOT.
    #[clap(long, default_value = "1")]
    exchange_rate: u128,

    /// Timeout for exchange rate setter, default 30 minutes.
    #[clap(long, default_value = "1800000")]
    timeout_ms: u64,

    /// Keyring for authorized oracle.
    #[clap(long, default_value = "bob")]
    keyring: AccountKeyring,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    let timeout = Duration::from_millis(opts.timeout_ms);

    loop {
        info!("Setting exchange rate at {}", chrono::offset::Local::now());
        match provider.set_exchange_rate_info(opts.exchange_rate).await {
            Err(e) => error!("Error: {}", e.to_string()),
            _ => (),
        };
        delay_for(timeout).await;
    }
}
