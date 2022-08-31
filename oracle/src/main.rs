mod currency;
mod error;
mod feeds;
mod routes;

use backoff::{future::retry_notify, ExponentialBackoff};
use clap::Parser;
use currency::*;
use error::Error;
use futures::future::join_all;
use git_version::git_version;
use runtime::{
    cli::{parse_duration_ms, ProviderUserOpts},
    FixedU128, InterBtcParachain, InterBtcSigner, OracleKey, OraclePallet,
};
use std::{convert::TryInto, time::Duration};
use tokio::{join, time::sleep};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const CONFIRMATION_TARGET: u32 = 1;
const BASE_CURRENCY: Currency = BTC;

#[derive(Parser)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Keyring / keyfile options
    #[clap(flatten)]
    account_info: ProviderUserOpts,

    /// Parachain URL, can be over WebSockets or HTTP
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    btc_parachain_url: String,

    /// Timeout in milliseconds to wait for connection to btc-parachain
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "60000")]
    connection_timeout_ms: Duration,

    /// Interval for exchange rate setter, default 25 minutes
    #[clap(long, parse(try_from_str = parse_duration_ms), default_value = "1500000")]
    interval_ms: Duration,

    /// Quote currency for exchange rates, e.g. "DOT" or "KSM"
    #[clap(long)]
    currency: Vec<Currency>,

    /// Take median of price sources
    #[clap(long)]
    median: bool,

    /// Connection settings for Blockstream
    #[clap(flatten)]
    blockstream: feeds::BlockstreamCli,

    /// Connection settings for BlockCypher
    #[clap(flatten)]
    blockcypher: feeds::BlockCypherCli,

    /// Connection settings for CoinGecko
    #[clap(flatten)]
    coingecko: feeds::CoinGeckoCli,

    /// Connection settings for gate.io
    #[clap(flatten)]
    gateio: feeds::GateIoCli,

    /// Connection settings for Kraken
    #[clap(flatten)]
    kraken: feeds::KrakenCli,
}

fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(5 * 60)), // elapse after 5 minutes
        max_interval: Duration::from_secs(20),               // wait at most 20 seconds before retrying
        multiplier: 2.0,                                     // delay doubles every time
        ..Default::default()
    }
}

async fn submit_bitcoin_fees(parachain_rpc: &InterBtcParachain, bitcoin_fee: f64) -> Result<(), Error> {
    log::info!(
        "Attempting to set fee estimate: {} sat/byte ({})",
        bitcoin_fee,
        chrono::offset::Local::now()
    );

    parachain_rpc
        .set_bitcoin_fees(FixedU128::from_float(bitcoin_fee))
        .await?;

    log::info!(
        "Successfully set fee estimate: {} sat/byte ({})",
        bitcoin_fee,
        chrono::offset::Local::now()
    );

    Ok(())
}

async fn submit_exchange_rate(
    parachain_rpc: &InterBtcParachain,
    currency_pair_and_price: &CurrencyPairAndPrice,
) -> Result<(), Error> {
    log::info!(
        "Attempting to set exchange rate: {} ({})",
        currency_pair_and_price,
        chrono::offset::Local::now()
    );

    let key = OracleKey::ExchangeRate(currency_pair_and_price.pair.quote.try_into()?);
    let exchange_rate = currency_pair_and_price
        .exchange_rate()
        .ok_or(Error::InvalidExchangeRate)?;
    parachain_rpc.feed_values(vec![(key, exchange_rate)]).await?;

    log::info!(
        "Successfully set exchange rate: {} ({})",
        currency_pair_and_price,
        chrono::offset::Local::now()
    );

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    log::info!("Starting oracle with currencies = {:?}", opts.currency);

    let mut price_feeds = feeds::PriceFeeds::new();
    price_feeds.add_coingecko(opts.coingecko);
    price_feeds.add_gateio(opts.gateio);
    price_feeds.add_kraken(opts.kraken);

    let mut bitcoin_feeds = feeds::BitcoinFeeds::new();
    bitcoin_feeds.add_blockstream(opts.blockstream);
    bitcoin_feeds.add_blockcypher(opts.blockcypher);

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(key_pair);

    loop {
        // TODO: retry these calls on failure
        let fee_estimates = if opts.median {
            vec![bitcoin_feeds.get_median(CONFIRMATION_TARGET).await?]
        } else {
            bitcoin_feeds.get_fee_estimates(CONFIRMATION_TARGET).await?
        };

        let prices = if opts.median {
            join_all(opts.currency.iter().map(|quote| {
                price_feeds.get_median(CurrencyPair {
                    base: BASE_CURRENCY,
                    quote: *quote,
                })
            }))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
        } else {
            join_all(opts.currency.iter().map(|quote| {
                price_feeds.get_prices(CurrencyPair {
                    base: BASE_CURRENCY,
                    quote: *quote,
                })
            }))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .concat()
        };

        // get prices above first to prevent websocket timeout
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let parachain_rpc = InterBtcParachain::from_url_with_retry(
            &opts.btc_parachain_url,
            signer.clone(),
            opts.connection_timeout_ms,
            shutdown_tx,
        )
        .await?;

        let (left, right) =
            join!(
                retry_notify(
                    get_exponential_backoff(),
                    || async {
                        join_all(
                            fee_estimates
                                .iter()
                                .map(|fee_estimate| submit_bitcoin_fees(&parachain_rpc, *fee_estimate)),
                        )
                        .await
                        .into_iter() // turn vec<result> into result
                        .find(|x| x.is_err())
                        .transpose()
                        .map_err(Into::into)
                    },
                    |err, _| log::error!("Error: {}", err),
                ),
                retry_notify(
                    get_exponential_backoff(),
                    || async {
                        join_all(prices.iter().map(|currency_pair_and_price| {
                            submit_exchange_rate(&parachain_rpc, currency_pair_and_price)
                        }))
                        .await
                        .into_iter() // turn vec<result> into result
                        .find(|x| x.is_err())
                        .transpose()
                        .map_err(Into::into)
                    },
                    |err, _| log::error!("Error: {}", err),
                )
            );

        if left.is_err() || right.is_err() {
            // exit if either task failed after backoff
            // error should already be logged
            return Err(Error::Shutdown);
        }

        sleep(opts.interval_ms).await;
    }
}
