mod error;

use backoff::{future::retry_notify, ExponentialBackoff};
use clap::Parser;
use error::Error;
use futures::future::join_all;
use git_version::git_version;
use reqwest::Url;
use runtime::{
    cli::{parse_duration_ms, ProviderUserOpts},
    CurrencyId, CurrencyIdExt, CurrencyInfo, FixedPointNumber,
    FixedPointTraits::{CheckedDiv, CheckedMul, One},
    FixedU128, InterBtcParachain, InterBtcSigner, OracleKey, OraclePallet,
};
use std::{collections::HashMap, time::Duration};
use tokio::{join, time::sleep};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const CONFIRMATION_TARGET: u32 = 1;

const BTC_DECIMALS: u32 = 8;
const BTC_CURRENCY: &str = "btc";

const COINGECKO_API_KEY_PARAMETER: &str = "x_cg_pro_api_key";

async fn get_exchange_rate_from_coingecko(currency_id: CurrencyId, url: &Url) -> Result<FixedU128, Error> {
    // https://www.coingecko.com/api/documentations/v3
    let resp = reqwest::get(url.clone())
        .await?
        .json::<HashMap<String, HashMap<String, f64>>>()
        .await?;

    let currency_name = currency_id.inner()?.name().to_lowercase();
    let exchange_rate = *resp
        .get(&currency_name)
        .ok_or(Error::InvalidResponse)?
        .get(BTC_CURRENCY)
        .ok_or(Error::InvalidResponse)?;

    FixedU128::one()
        .checked_div(&FixedU128::from_float(exchange_rate))
        .ok_or(Error::InvalidExchangeRate)
}

async fn get_bitcoin_fee_estimate_from_blockstream(url: &Url) -> Result<FixedU128, Error> {
    // https://github.com/Blockstream/esplora/blob/master/API.md
    let resp = reqwest::get(url.clone()).await?.json::<HashMap<u32, f64>>().await?;

    let fee_estimate = *resp.get(&CONFIRMATION_TARGET).ok_or(Error::InvalidResponse)?;
    FixedU128::checked_from_integer(fee_estimate.round() as u128).ok_or(Error::InvalidFeeEstimate)
}

fn parse_fixed_point(src: &str) -> Result<FixedU128, Error> {
    FixedU128::checked_from_integer(src.parse::<u128>()?).ok_or(Error::InvalidExchangeRate)
}

pub fn parse_collateral_and_optional_rate(
    s: &str,
) -> Result<(String, Option<FixedU128>), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let parts: Vec<_> = s.split("=").collect();
    match parts.as_slice() {
        &[currency, rate] => Ok((currency.to_string(), Some(parse_fixed_point(rate)?))),
        &[currency] => Ok((currency.to_string(), None)),
        _ => Err(Box::new(Error::InvalidArguments)),
    }
}

#[derive(Parser)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    btc_parachain_url: String,

    /// Estimated fee rate to include a Bitcoin transaction
    /// in the next block (~10 min).
    #[clap(long, parse(try_from_str = parse_fixed_point), default_value = "1")]
    bitcoin_fee: FixedU128,

    /// Collateral type for exchange rates, e.g. "DOT" or "KSM". The exchange rate
    /// will be fetched from coingecko unless explicitly set as e.g. "KSM=123", in which
    /// case the given exchange rate will be used. The rate will be in while units e.g. KSM/BTC.
    #[clap(long, parse(try_from_str = parse_collateral_and_optional_rate))]
    currency_id: Vec<(String, Option<FixedU128>)>,

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
    #[clap(long)]
    coingecko: Option<Url>,

    /// Use a dedicated API key for coingecko pro URL (https://pro-api.coingecko.com/api/v3/)
    #[clap(long)]
    coingecko_api_key: Option<String>,

    /// Timeout in milliseconds to wait for connection to btc-parachain.
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "60000")]
    connection_timeout_ms: Duration,
}

#[derive(Clone)]
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
    currency_id: CurrencyId,
    conversion_factor: FixedU128,
) -> Result<(), Error> {
    let exchange_rate = match url_or_def {
        UrlOrDefault::Url(url) => {
            // exchange_rate given in BTC/DOT so convert after
            get_exchange_rate_from_coingecko(currency_id, &url).await?
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

    let key = OracleKey::ExchangeRate(currency_id);
    Ok(parachain_rpc.feed_values(vec![(key, exchange_rate)]).await?)
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

    log::info!("Starting oracle with currencies = {:?}", opts.currency_id);

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(key_pair);

    let blockstream_url = if let Some(mut url) = opts.blockstream.clone() {
        url.set_path(&format!("{}/fee-estimates", url.path()));
        Some(url)
    } else {
        None
    };

    let parsed_currency_ids = {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let parachain_rpc = &InterBtcParachain::from_url_with_retry(
            &opts.btc_parachain_url,
            signer.clone(),
            opts.connection_timeout_ms,
            shutdown_tx,
        )
        .await?;

        join_all(opts.currency_id.iter().map(|(symbol, amount)| async move {
            Ok((
                parachain_rpc.parse_currency_id(symbol.to_string()).await?,
                amount.clone(),
            ))
        }))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?
    };

    let exchange_rates_to_set = parsed_currency_ids
        .into_iter()
        .map(|(currency_id, explicit_exchange_rate)| match explicit_exchange_rate {
            Some(rate) => Ok((currency_id, UrlOrDefault::Def(rate.clone()))),
            None => {
                let mut url = match &opts.coingecko {
                    Some(x) => x.clone(),
                    None => {
                        return Err(Error::InvalidArguments);
                    }
                };
                url.set_path(&format!("{}/simple/price", url.path()));
                url.set_query(Some(&format!(
                    "ids={}&vs_currencies={}",
                    currency_id.inner().unwrap().name().to_lowercase(),
                    BTC_CURRENCY
                )));
                if let Some(api_key) = &opts.coingecko_api_key {
                    url.query_pairs_mut().append_pair(COINGECKO_API_KEY_PARAMETER, api_key);
                }
                Ok((currency_id, UrlOrDefault::Url(url)))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    // append the conversion_factor
    let exchange_rates_to_set: Vec<_> = exchange_rates_to_set
        .into_iter()
        .map(|(currency_id, value)| {
            let conversion_factor = FixedU128::checked_from_rational(
                10_u128.pow(currency_id.inner().unwrap().decimals() as u32),
                10_u128.pow(BTC_DECIMALS),
            )
            .unwrap();
            (currency_id, value, conversion_factor)
        })
        .collect();

    loop {
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let parachain_rpc = InterBtcParachain::from_url_with_retry(
            &opts.btc_parachain_url,
            signer.clone(),
            opts.connection_timeout_ms,
            shutdown_tx,
        )
        .await?;

        let bitcoin_fee = opts.bitcoin_fee;

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
                    let result = futures::future::join_all(exchange_rates_to_set.iter().map(
                        |(currency_id, value, conversion_factor)| {
                            submit_exchange_rate(&parachain_rpc, value.clone(), *currency_id, *conversion_factor)
                        },
                    ))
                    .await
                    .into_iter() // turn vec<result> into result
                    .find(|x| x.is_err())
                    .transpose();
                    Ok(result?)
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
