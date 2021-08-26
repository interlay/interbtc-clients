mod error;

use backoff::{future::retry_notify, ExponentialBackoff};
use clap::Clap;
use error::Error;
use git_version::git_version;
use reqwest::Url;
use runtime::{
    cli::{parse_duration_ms, ProviderUserOpts},
    substrate_subxt::PairSigner,
    FixedPointNumber,
    FixedPointTraits::CheckedMul,
    FixedU128, InterBtcParachain, InterBtcRuntime, OraclePallet,
};
use std::{collections::HashMap, time::Duration};
use tokio::{join, time::sleep};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const CONFIRMATION_TARGET: u32 = 1;
const BTC_DECIMALS: u32 = 8;
const DOT_DECIMALS: u32 = 10;

async fn get_exchange_rate_from_coingecko(url: &Url) -> Result<FixedU128, Error> {
    // https://www.coingecko.com/api/documentations/v3
    let resp = reqwest::get(url.clone())
        .await?
        .json::<HashMap<String, HashMap<String, u128>>>()
        .await?;

    let exchange_rate = *resp
        .get("bitcoin")
        .ok_or(Error::InvalidResponse)?
        .get("dot")
        .ok_or(Error::InvalidResponse)?;

    FixedU128::checked_from_integer(exchange_rate).ok_or(Error::InvalidExchangeRate)
}

async fn get_bitcoin_fee_estimate_from_blockstream(url: &Url) -> Result<FixedU128, Error> {
    // https://github.com/Blockstream/esplora/blob/master/API.md
    let resp = reqwest::get(url.clone()).await?.json::<HashMap<u32, f64>>().await?;

    let fee_estimate = *resp.get(&CONFIRMATION_TARGET).ok_or(Error::InvalidResponse)?;
    FixedU128::checked_from_integer(fee_estimate.round() as u128).ok_or(Error::InvalidFeeEstimate)
}

pub fn parse_fixed_point(src: &str) -> Result<FixedU128, Error> {
    FixedU128::checked_from_integer(src.parse::<u128>()?).ok_or(Error::InvalidExchangeRate)
}

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    btc_parachain_url: String,

    /// Estimated fee rate to include a Bitcoin transaction
    /// in the next block (~10 min).
    #[clap(long, parse(try_from_str = parse_fixed_point), default_value = "1")]
    bitcoin_fee: FixedU128,

    /// Exchange rate from the collateral currency to
    /// the wrapped currency - i.e. 1 BTC = 2308 DOT.
    #[clap(long, parse(try_from_str = parse_fixed_point), default_value = "2308")]
    exchange_rate: FixedU128,

    /// Interval for exchange rate setter, default 25 minutes.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "1500000")]
    interval_ms: Duration,

    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: ProviderUserOpts,

    /// Fetch the bitcoin fee from Blockstream (https://blockstream.info/api/).
    #[clap(long, conflicts_with("bitcoin-fee"))]
    blockstream: Option<Url>,

    /// Fetch the exchange rate from CoinGecko (https://api.coingecko.com/api/v3/).
    #[clap(long, conflicts_with("exchange-rate"))]
    coingecko: Option<Url>,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "60000")]
    connection_timeout_ms: Duration,
}

enum UrlOrDefault<DEF> {
    Url(Url),
    Def(DEF),
}

impl<DEF> UrlOrDefault<DEF> {
    fn from_args(maybe_url: Option<Url>, def: DEF) -> Self {
        if let Some(url) = maybe_url {
            Self::Url(url)
        } else {
            Self::Def(def)
        }
    }
}

fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(5 * 60)), // elapse after 5 minutes
        max_interval: Duration::from_secs(20),               // wait at most 20 seconds before retrying
        multiplier: 2.0,                                     // delay doubles every time
        ..Default::default()
    }
}

/// Fetches the exchange rate from CoinGecko or uses the provided default.
/// This is then converted into the expected format and submitted.
async fn submit_exchange_rate(
    parachain_rpc: &InterBtcParachain,
    url_or_def: UrlOrDefault<FixedU128>,
    conversion_factor: FixedU128,
) -> Result<(), Error> {
    let exchange_rate = match url_or_def {
        UrlOrDefault::Url(url) => {
            // exchange_rate given in BTC/DOT so convert after
            get_exchange_rate_from_coingecko(&url).await?
        }
        UrlOrDefault::Def(def) => def,
    };

    let exchange_rate = exchange_rate
        .checked_mul(&conversion_factor)
        .ok_or(Error::InvalidExchangeRate)?;

    log::info!(
        "Setting exchange rate: {} ({})",
        exchange_rate,
        chrono::offset::Local::now()
    );

    Ok(parachain_rpc.set_exchange_rate(exchange_rate).await?)
}

/// Fetches the Bitcoin fee estimate from Blockstream or uses the provided default.
/// This is then converted into the expected format and submitted.
async fn submit_bitcoin_fees(
    parachain_rpc: &InterBtcParachain,
    url_or_def: UrlOrDefault<FixedU128>,
) -> Result<(), Error> {
    let bitcoin_fee = match url_or_def {
        UrlOrDefault::Url(url) => get_bitcoin_fee_estimate_from_blockstream(&url).await?,
        UrlOrDefault::Def(def) => def,
    };

    log::info!(
        "Setting fee estimate: {} ({})",
        bitcoin_fee,
        chrono::offset::Local::now()
    );

    Ok(parachain_rpc.set_bitcoin_fees(bitcoin_fee).await?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<InterBtcRuntime, _>::new(key_pair);

    let blockstream_url = if let Some(mut url) = opts.blockstream {
        url.set_path(&format!("{}/fee-estimates", url.path()));
        Some(url)
    } else {
        None
    };

    // TODO: configurable collateral currencies
    let coingecko_url = if let Some(mut url) = opts.coingecko {
        url.set_path(&format!("{}/simple/price", url.path()));
        url.set_query(Some("ids=bitcoin&vs_currencies=dot"));
        Some(url)
    } else {
        None
    };

    let conversion_factor =
        FixedU128::checked_from_rational(10_u128.pow(DOT_DECIMALS), 10_u128.pow(BTC_DECIMALS)).unwrap();

    loop {
        let parachain_rpc =
            InterBtcParachain::from_url_with_retry(&opts.btc_parachain_url, signer.clone(), opts.connection_timeout_ms)
                .await?;

        let bitcoin_fee = opts.bitcoin_fee;
        let exchange_rate = opts.exchange_rate;

        let (left, right) = join!(
            retry_notify(
                get_exponential_backoff(),
                || async {
                    Ok(submit_bitcoin_fees(
                        &parachain_rpc,
                        UrlOrDefault::from_args(blockstream_url.clone(), bitcoin_fee),
                    )
                    .await?)
                },
                |err, _| log::error!("Error: {}", err),
            ),
            retry_notify(
                get_exponential_backoff(),
                || async {
                    Ok(submit_exchange_rate(
                        &parachain_rpc,
                        UrlOrDefault::from_args(coingecko_url.clone(), exchange_rate),
                        conversion_factor,
                    )
                    .await?)
                },
                |err, _| log::error!("Error: {}", err),
            ),
        );

        if left.is_err() || right.is_err() {
            // exit if either task failed after backoff
            // error should already be logged
            return Err(Error::Shutdown);
        }

        sleep(opts.interval_ms).await;
    }
}
