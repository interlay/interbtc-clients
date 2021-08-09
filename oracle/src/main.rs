mod error;

use clap::Clap;
use error::Error;
use git_version::git_version;
use log::{error, info};
use runtime::{
    substrate_subxt::PairSigner, ExchangeRateOraclePallet, FixedPointNumber, FixedPointTraits::CheckedMul, FixedU128,
    InterBtcParachain, InterBtcRuntime,
};
use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const ERR_RETRY_WAIT: Duration = Duration::from_secs(10);

async fn get_exchange_rate_from_coingecko() -> Result<u128, Error> {
    // https://www.coingecko.com/api/documentations/v3
    let resp = reqwest::get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=dot")
        .await?
        .json::<HashMap<String, HashMap<String, u128>>>()
        .await?;

    Ok(*resp
        .get("bitcoin")
        .ok_or(Error::InvalidExchangeRate)?
        .get("dot")
        .ok_or(Error::InvalidExchangeRate)?)
}

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    btc_parachain_url: String,

    /// Exchange rate from the collateral currency to
    /// the wrapped currency - i.e. 1 BTC = 2308 DOT.
    #[clap(long, default_value = "2308")]
    exchange_rate: u128,

    /// Number of decimals for the collateral currency.
    #[clap(long, default_value = "10")]
    collateral_decimals: u32,

    /// Number of decimals for the wrapped currency.
    #[clap(long, default_value = "8")]
    wrapped_decimals: u32,

    /// Interval for exchange rate setter, default 25 minutes.
    #[clap(long, default_value = "1500000")]
    interval_ms: u64,

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
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<InterBtcRuntime, _>::new(key_pair);

    let interval = Duration::from_millis(opts.interval_ms);
    let exchange_rate = FixedU128::checked_from_integer(opts.exchange_rate).ok_or(Error::InvalidExchangeRate)?;

    let conversion_factor = FixedU128::checked_from_rational(
        10_u128.pow(opts.collateral_decimals),
        10_u128.pow(opts.wrapped_decimals),
    )
    .unwrap();

    loop {
        let exchange_rate = if opts.coingecko {
            match get_exchange_rate_from_coingecko().await {
                Ok(exchange_rate) => {
                    // exchange_rate given in BTC/DOT so there is no need to adjust
                    FixedU128::checked_from_integer(exchange_rate).unwrap()
                }
                Err(err) => {
                    error!("Could not get exchange rate from CoinGecko: {}", err);
                    sleep(ERR_RETRY_WAIT).await;
                    continue;
                }
            }
        } else {
            exchange_rate
        };

        let exchange_rate = exchange_rate
            .checked_mul(&conversion_factor)
            .ok_or(Error::InvalidExchangeRate)?;

        info!(
            "Setting exchange rate: {} ({})",
            exchange_rate,
            chrono::offset::Local::now()
        );

        let result = InterBtcParachain::from_url_with_retry(
            &opts.btc_parachain_url.clone(),
            signer.clone(),
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?
        .set_exchange_rate(exchange_rate)
        .await;

        if let Err(e) = result {
            error!("Error: {}", e.to_string());
        }

        sleep(interval).await;
    }
}
