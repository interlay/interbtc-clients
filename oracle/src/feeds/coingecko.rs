use super::{get_http, PriceFeed};
use crate::{currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;

const COINGECKO_API_KEY_PARAMETER: &str = "x_cg_pro_api_key";

#[derive(Parser, Debug, Clone)]
pub struct CoinGeckoCli {
    /// Fetch the exchange rate from CoinGecko (https://api.coingecko.com/api/v3/).
    #[clap(long)]
    coingecko_url: Option<Url>,

    /// Use a dedicated API key for coingecko pro URL (https://pro-api.coingecko.com/api/v3/)
    #[clap(long)]
    coingecko_api_key: Option<String>,
}

pub struct CoinGeckoApi {
    url: Url,
    api_key: Option<String>,
}

impl Default for CoinGeckoApi {
    fn default() -> Self {
        Self {
            url: Url::parse("https://api.coingecko.com/api/v3").unwrap(),
            api_key: None,
        }
    }
}

impl CoinGeckoApi {
    pub fn from_opts(opts: CoinGeckoCli) -> Option<Self> {
        if let Some(url) = opts.coingecko_url {
            let mut api = Self::new(url);
            if let Some(api_key) = opts.coingecko_api_key {
                api.with_key(api_key)
            }
            Some(api)
        } else {
            None
        }
    }

    pub fn new(url: Url) -> Self {
        Self { url, api_key: None }
    }

    pub fn with_key(&mut self, api_key: String) {
        self.api_key = Some(api_key);
    }

    async fn get_exchange_rate(&self, base: &str, quote: &str) -> Result<f64, Error> {
        // https://www.coingecko.com/api/documentations/v3
        let mut url = self.url.clone();
        url.set_path(&format!("{}/simple/price", url.path()));
        url.set_query(Some(&format!(
            "ids={}&vs_currencies={}",
            base.to_lowercase(),
            quote.to_lowercase(),
        )));
        if let Some(api_key) = &self.api_key {
            url.query_pairs_mut().append_pair(COINGECKO_API_KEY_PARAMETER, api_key);
        }

        let exchange_rate = get_http(url)
            .await?
            .get(&base.to_lowercase())
            .ok_or(Error::InvalidResponse)?
            .get(&quote.to_lowercase())
            .ok_or(Error::InvalidResponse)?
            .as_f64()
            .ok_or(Error::InvalidResponse)?;

        Ok(exchange_rate)
    }
}

#[async_trait]
impl PriceFeed for CoinGeckoApi {
    async fn get_price(&self, currency_pair: CurrencyPair) -> Result<CurrencyPairAndPrice, Error> {
        let price = self
            .get_exchange_rate(currency_pair.base.name(), currency_pair.quote.symbol())
            .await?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price,
        })
    }
}
