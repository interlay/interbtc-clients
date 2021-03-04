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

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, default_value = "60000")]
    connection_timeout_ms: u64,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        log::LevelFilter::Info.as_str(),
    ));
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);
    let provider = Arc::new(
        PolkaBtcProvider::from_url_with_retry(
            opts.polka_btc_url,
            signer,
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?,
    );

    let timeout = Duration::from_millis(opts.timeout_ms);
    let exchange_rate = FixedU128::checked_from_rational(opts.exchange_rate, 100_000)
        .ok_or(Error::InvalidExchangeRate)?;

    loop {
        let exchange_rate = if opts.coingecko {
            match get_exchange_rate_from_coingecko().await {
                Ok(exchange_rate) => {
                    // exchange_rate given in BTC/DOT so there is no need to adjust
                    FixedU128::checked_from_integer(exchange_rate).unwrap()
                }
                Err(err) => {
                    error!("Could not get exchange rate from CoinGecko: {}", err);
                    delay_for(ERR_RETRY_WAIT).await;
                    continue;
                }
            }
        } else {
            exchange_rate
        };

        info!(
            "Setting exchange rate: {} ({})",
            exchange_rate,
            chrono::offset::Local::now()
        );

        match provider.set_exchange_rate_info(exchange_rate).await {
            Err(e) => error!("Error: {}", e.to_string()),
            _ => (),
        };
        delay_for(timeout).await;
    }
}
