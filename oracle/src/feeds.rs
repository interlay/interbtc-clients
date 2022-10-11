mod blockcypher;
mod blockstream;
mod coingecko;
mod gateio;
mod kraken;

use crate::{
    config::{CurrencyStore, PriceConfig},
    currency::*,
    Error,
};
use async_trait::async_trait;
use futures::future::join_all;
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use statrs::statistics::{Data, OrderStatistics};
use std::{collections::BTreeMap, fmt};

pub use blockcypher::{BlockCypherApi, BlockCypherCli};
pub use blockstream::{BlockstreamApi, BlockstreamCli};
pub use coingecko::{CoinGeckoApi, CoinGeckoCli};
pub use gateio::{GateIoApi, GateIoCli};
pub use kraken::{KrakenApi, KrakenCli};

pub async fn get_http(url: Url) -> Result<Value, Error> {
    log::debug!("{}", url);
    // TODO: share http client
    Ok(reqwest::get(url).await?.error_for_status()?.json::<Value>().await?)
}

#[derive(Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[serde(rename_all = "lowercase")]
pub enum FeedName {
    Kraken,
    GateIo,
    CoinGecko,
}

impl fmt::Display for FeedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[async_trait]
trait PriceFeed {
    async fn get_price(
        &self,
        currency_pair: CurrencyPair,
        currency_store: &CurrencyStore,
    ) -> Result<CurrencyPairAndPrice, Error>;
}

#[derive(Default)]
pub struct PriceFeeds {
    currency_store: CurrencyStore,
    feeds: BTreeMap<FeedName, Box<dyn PriceFeed>>,
}

impl PriceFeeds {
    pub fn new(currency_store: CurrencyStore) -> Self {
        Self {
            currency_store,
            ..Default::default()
        }
    }

    pub fn add_coingecko(&mut self, opts: CoinGeckoCli) {
        if let Some(api) = CoinGeckoApi::from_opts(opts) {
            log::info!("🔗 CoinGecko");
            self.feeds.insert(FeedName::CoinGecko, Box::new(api));
        }
    }

    pub fn add_gateio(&mut self, opts: GateIoCli) {
        if let Some(api) = GateIoApi::from_opts(opts) {
            log::info!("🔗 gate.io");
            self.feeds.insert(FeedName::GateIo, Box::new(api));
        }
    }

    pub fn add_kraken(&mut self, opts: KrakenCli) {
        if let Some(api) = KrakenApi::from_opts(opts) {
            log::info!("🔗 Kraken");
            self.feeds.insert(FeedName::Kraken, Box::new(api));
        }
    }

    pub async fn get_prices(&self, price_config: PriceConfig) -> Result<Vec<CurrencyPairAndPrice>, Error> {
        let currency_pair = price_config.pair;
        let currency_store = &self.currency_store;
        Ok(join_all(
            price_config
                .feeds
                .into_iter()
                .filter_map(|(name, route)| self.feeds.get(&name).map(|feed| (name, route, feed)))
                .map(|(name, route, feed)| {
                    let currency_pair = currency_pair.clone();
                    async move {
                        let mut currency_pair_and_price = if let Some(currency_pair_and_price) = join_all(
                            route
                                .into_iter()
                                .map(|currency_pair| feed.get_price(currency_pair.into(), currency_store)),
                        )
                        .await
                        .into_iter()
                        .collect::<Result<Vec<_>, Error>>()?
                        .into_iter()
                        .reduce(|left, right| left.reduce(right))
                        {
                            currency_pair_and_price
                        } else {
                            return Ok(None);
                        };

                        if currency_pair_and_price.pair.base != currency_pair.base {
                            currency_pair_and_price = currency_pair_and_price.invert()
                        }

                        log::trace!("Using {:?}: {}", name, currency_pair_and_price);
                        Ok(Some(currency_pair_and_price))
                    }
                }),
        )
        .await
        .into_iter()
        .collect::<Result<Vec<_>, Error>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>())
    }

    pub async fn get_median(&self, price_config: PriceConfig) -> Result<CurrencyPairAndPrice, Error> {
        Ok(CurrencyPairAndPrice {
            pair: price_config.pair.clone(),
            price: Data::new(
                self.get_prices(price_config)
                    .await?
                    .into_iter()
                    .map(|cup| cup.price)
                    .collect::<Vec<f64>>(),
            )
            .median(),
        })
    }
}

#[async_trait]
trait BitcoinFeed {
    async fn get_fee_estimate(&self, confirmation_target: u32) -> Result<f64, Error>;
}

pub struct BitcoinFeeds(Vec<Box<dyn BitcoinFeed>>);

impl BitcoinFeeds {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn add_blockstream(&mut self, opts: BlockstreamCli) {
        if let Some(api) = BlockstreamApi::from_opts(opts) {
            log::info!("🔗 Blockstream");
            self.0.push(Box::new(api));
        }
    }

    pub fn add_blockcypher(&mut self, opts: BlockCypherCli) {
        if let Some(api) = BlockCypherApi::from_opts(opts) {
            log::info!("🔗 BlockCypher");
            self.0.push(Box::new(api));
        }
    }

    pub async fn get_fee_estimates(&self, confirmation_target: u32) -> Result<Vec<f64>, Error> {
        join_all(self.0.iter().map(|feed| feed.get_fee_estimate(confirmation_target)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, Error>>()
    }

    pub async fn get_median(&self, confirmation_target: u32) -> Result<f64, Error> {
        Ok(Data::new(self.get_fee_estimates(confirmation_target).await?).median())
    }
}
