use super::{get_http, PriceFeed};
use crate::{config::CurrencyStore, currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;
use serde_json::Value;

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

fn extract_response(value: Value, base: &str, quote: &str) -> Option<f64> {
    value.get(base)?.get(quote)?.as_f64()
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

    async fn get_exchange_rate(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<String>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        let base = currency_pair
            .base
            .path()
            .or_else(|| Some(currency_store.name(&currency_pair.base.symbol())?.to_lowercase()))
            .ok_or(Error::InvalidCurrency)?;
        let quote = currency_pair
            .quote
            .path()
            .unwrap_or_else(|| currency_pair.quote.symbol().to_lowercase());

        // https://www.coingecko.com/api/documentations/v3
        let mut url = self.url.clone();
        url.set_path(&format!("{}/simple/price", url.path()));
        url.set_query(Some(&format!("ids={base}&vs_currencies={quote}")));
        if let Some(api_key) = &self.api_key {
            url.query_pairs_mut().append_pair(COINGECKO_API_KEY_PARAMETER, api_key);
        }

        let data = get_http(url).await?;
        let exchange_rate = extract_response(data, &base, &quote).ok_or(Error::InvalidResponse)?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price: exchange_rate,
        })
    }
}

#[async_trait]
impl PriceFeed for CoinGeckoApi {
    async fn get_price(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<String>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        self.get_exchange_rate(currency_pair, currency_store).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn should_extract_response() {
        assert_eq!(
            extract_response(
                json!({
                    "bitcoin":{"usd":19148.24}
                }),
                "bitcoin",
                "usd"
            ),
            Some(19148.24)
        )
    }
}
