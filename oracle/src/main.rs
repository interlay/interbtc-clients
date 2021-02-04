mod error;

use clap::Clap;
use error::Error;
use log::{error, info};
use runtime::substrate_subxt::PairSigner;
use runtime::{
    ExchangeRateOraclePallet, FixedPointNumber, FixedU128, PolkaBtcProvider, PolkaBtcRuntime,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

const ERR_RETRY_WAIT: Duration = Duration::from_secs(10);

async fn get_exchange_rate_from_coingecko() -> Result<u128, Error> {
    // https://www.coingecko.com/api/documentations/v3
    let resp =
        reqwest::get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=dot")
            .await?
            .json::<HashMap<String, HashMap<String, u128>>>()
            .await?;

    Ok(*resp
        .get("bitcoin")
        .ok_or(Error::InvalidExchangeRate)?
        .get("dot")
        .ok_or(Error::InvalidExchangeRate)?)
}

/// Simple oracle liveness service to automatically update the
/// exchange rate periodically.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Exchange rate from Planck to Satoshi.
    /// hardcoded to 1 BTC = 3855.23187 DOT
    /// at granularity of 5
    #[clap(long, default_value = "385523187")]
    exchange_rate: u128,

    /// Timeout for exchange rate setter, default 30 minutes.
    #[clap(long, default_value = "1800000")]
    timeout_ms: u64,

    /// keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Fetch the exchange rate from CoinGecko.
    #[clap(long, conflicts_with("exchange-rate"))]
    coingecko: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let provider = Arc::new(PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?);

    let timeout = Duration::from_millis(opts.timeout_ms);
    let mut exchange_rate = opts.exchange_rate;

    loop {
        if opts.coingecko {
            exchange_rate = match get_exchange_rate_from_coingecko().await {
                Ok(exchange_rate) => exchange_rate,
                Err(e) => {
                    error!("Could not get exchange rate: {}", e.to_string());
                    delay_for(ERR_RETRY_WAIT).await;
                    continue;
                }
            }
        }

        info!(
            "Setting exchange rate: {} ({})",
            exchange_rate,
            chrono::offset::Local::now()
        );

        match FixedU128::checked_from_rational(exchange_rate, 100_000) {
            Some(rate) => match provider.set_exchange_rate_info(rate).await {
                Err(e) => error!("Error: {}", e.to_string()),
                _ => (),
            },
            None => error!("Failed to construct fixed point rational"),
        };
        delay_for(timeout).await;
    }
}
