use super::{get_http, PriceFeed};
use crate::{currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;

#[derive(Parser, Debug, Clone)]
pub struct KrakenCli {
    /// Fetch the exchange rate from Kraken
    #[clap(long)]
    kraken_url: Option<Url>,
}

pub struct KrakenApi {
    url: Url,
}

impl Default for KrakenApi {
    fn default() -> Self {
        Self {
            url: Url::parse("https://api.kraken.com/0").unwrap(),
        }
    }
}

impl KrakenApi {
    pub fn from_opts(opts: KrakenCli) -> Option<Self> {
        opts.kraken_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(&self, currency_pair: CurrencyPair) -> Result<CurrencyPairAndPrice, Error> {
        // NOTE: Kraken prefixes older cryptocurrencies with "X" and fiat with "Z"
        let asset_pair_name = format!("{}{}", currency_pair.base.symbol(), currency_pair.quote.symbol());

        // https://docs.kraken.com/rest/
        let mut url = self.url.clone();
        url.set_path(&format!("{}/public/Ticker", url.path()));
        url.set_query(Some(&format!("pair={}", asset_pair_name)));

        // get today's opening price
        let exchange_rate = get_http(url)
            .await?
            .get("result")
            .ok_or(Error::InvalidResponse)?
            .as_object()
            .ok_or(Error::InvalidResponse)?
            .iter()
            .last() // we are only fetching one anyway
            .ok_or(Error::InvalidResponse)?
            .1
            .get("o")
            .ok_or(Error::InvalidResponse)?
            .as_str()
            .ok_or(Error::InvalidResponse)?
            .parse::<f64>()?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price: exchange_rate,
        })
    }
}

#[async_trait]
impl PriceFeed for KrakenApi {
    async fn get_price(&self, currency_pair: CurrencyPair) -> Result<CurrencyPairAndPrice, Error> {
        self.get_exchange_rate(currency_pair).await
    }
}
