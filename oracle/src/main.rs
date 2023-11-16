mod config;
mod currency;
mod error;
mod feeds;

use backoff::{future::retry_notify, ExponentialBackoff};
use clap::Parser;
use config::{CurrencyStore, OracleConfig, PriceConfig};
use currency::*;
use error::Error;
use feeds::CoinGeckoApi;
use futures::{future::join_all, stream::StreamExt};
use git_version::git_version;
use runtime::{
    cli::{parse_duration_ms, ProviderUserOpts},
    CurrencyId, FixedU128, InterBtcParachain, InterBtcSigner, OracleKey, OraclePallet, ShutdownSender, TryFromSymbol,
};
use signal_hook::consts::*;
use signal_hook_tokio::Signals;
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{join, time::sleep};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

const CONFIRMATION_TARGET: u32 = 1;

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
    #[clap(long, value_parser = parse_duration_ms, default_value = "60000")]
    connection_timeout_ms: Duration,

    /// Interval for exchange rate setter, default 25 minutes
    #[clap(long, value_parser = parse_duration_ms, default_value = "1500000")]
    interval_ms: Duration,

    /// Connection settings for Blockstream
    #[clap(flatten)]
    blockstream: feeds::BlockstreamCli,

    /// Connection settings for BlockCypher
    #[clap(flatten)]
    blockcypher: feeds::BlockCypherCli,

    /// Connection settings for CoinGecko
    #[clap(flatten)]
    coingecko: feeds::CoinGeckoCli,

    /// Connection settings for Dia
    #[clap(flatten)]
    dia: feeds::DiaCli,

    /// Connection settings for DiaFairPrice
    #[clap(flatten)]
    dia_fair_price: feeds::DiaFairPriceCli,

    /// Connection settings for gate.io
    #[clap(flatten)]
    gateio: feeds::GateIoCli,

    /// Connection settings for Kraken
    #[clap(flatten)]
    kraken: feeds::KrakenCli,

    /// Feed / price config.
    #[clap(long, default_value = "./oracle-config.json")]
    oracle_config: PathBuf,
}

fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(5 * 60)), // elapse after 5 minutes
        max_interval: Duration::from_secs(20),               // wait at most 20 seconds before retrying
        multiplier: 2.0,                                     // delay doubles every time
        ..Default::default()
    }
}

async fn submit_bitcoin_fees(parachain_rpc: &InterBtcParachain, maybe_bitcoin_fee: Option<f64>) -> Result<(), Error> {
    let bitcoin_fee = if let Some(bitcoin_fee) = maybe_bitcoin_fee {
        bitcoin_fee
    } else {
        log::warn!("No fee estimate to submit");
        return Ok(());
    };

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
    currency_pair_and_price: &CurrencyPairAndPrice<Currency>,
    currency_store: &CurrencyStore<String>,
) -> Result<(), Error> {
    log::info!(
        "Attempting to set exchange rate: {} ({})",
        currency_pair_and_price,
        chrono::offset::Local::now()
    );

    let currency_id =
        CurrencyId::try_from_symbol(currency_pair_and_price.pair.quote.symbol()).map_err(Error::RuntimeError)?;
    let key = OracleKey::ExchangeRate(currency_id);
    let exchange_rate = currency_pair_and_price.exchange_rate(currency_store)?;
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
    let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT]).expect("Failed to set up signal listener.");

    tokio::select! {
        res = _main() => {
            if let Err(ref e) = res {
                log::error!("Error: {}", e);
            }
            res
        },
        signal_option = signals.next() => {
            if let Some(signal) = signal_option {
                log::info!("Received termination signal: {}", signal);
            }
            log::info!("Shutting down...");
            Ok(())
        }
    }
}

async fn _main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    // read price configs from file
    let data = std::fs::read_to_string(opts.oracle_config)?;
    let oracle_config = serde_json::from_str::<OracleConfig>(&data)?;
    // validate routes
    for price_config in &oracle_config.prices {
        price_config
            .validate()
            .map_err(|err| Error::InvalidConfig(Box::new(err)))?
    }

    let currency_store = &oracle_config.currencies;
    let mut price_feeds = feeds::PriceFeeds::new(currency_store.clone());
    price_feeds.maybe_add_coingecko(opts.coingecko.clone());
    price_feeds.maybe_add_dia(opts.dia);
    price_feeds.maybe_add_dia_fair_price(opts.dia_fair_price);
    price_feeds.maybe_add_gateio(opts.gateio);
    price_feeds.maybe_add_kraken(opts.kraken);

    let mut bitcoin_feeds = feeds::BitcoinFeeds::new();
    bitcoin_feeds.maybe_add_blockstream(opts.blockstream);
    bitcoin_feeds.maybe_add_blockcypher(opts.blockcypher);

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(key_pair);

    loop {
        // TODO: retry these calls on failure
        let fee_estimate = bitcoin_feeds.maybe_get_median(CONFIRMATION_TARGET).await?;
        let prices = join_all(
            oracle_config
                .prices
                .clone()
                .into_iter()
                .map(|price_config| price_feeds.get_value_or_median(price_config)),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

        log::debug!("Collected prices: {:?}", prices);

        // get prices above first to prevent websocket timeout
        let shutdown_tx = ShutdownSender::new();
        let parachain_rpc = InterBtcParachain::from_url_with_retry(
            &opts.btc_parachain_url,
            signer.clone(),
            opts.connection_timeout_ms,
            shutdown_tx,
        )
        .await?;

        let (left, right) = join!(
            retry_notify(
                get_exponential_backoff(),
                || async {
                    submit_bitcoin_fees(&parachain_rpc, fee_estimate)
                        .await
                        .map_err(Into::into)
                },
                |err, _| log::error!("Error: {}", err),
            ),
            retry_notify(
                get_exponential_backoff(),
                || async {
                    join_all(prices.iter().map(|currency_pair_and_price| {
                        submit_exchange_rate(&parachain_rpc, currency_pair_and_price, currency_store)
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
