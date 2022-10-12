use super::{get_http, PriceFeed};
use crate::{config::CurrencyStore, currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;
use serde_json::Value;

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

fn extract_response<'a>(value: &'a Value) -> Option<&'a str> {
    value
        .get("result")?
        .as_object()?
        .iter()
        .last()? // we are only fetching one anyway
        .1
        .get("o")?
        .as_str()
}

impl KrakenApi {
    pub fn from_opts(opts: KrakenCli) -> Option<Self> {
        opts.kraken_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<Currency>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        // NOTE: Kraken prefixes older cryptocurrencies with "X" and fiat with "Z"
        let asset_pair_name = format!(
            "{}{}",
            currency_store.symbol(&currency_pair.base)?,
            currency_store.symbol(&currency_pair.quote)?,
        );

        // https://docs.kraken.com/rest/
        let mut url = self.url.clone();
        url.set_path(&format!("{}/public/Ticker", url.path()));
        url.set_query(Some(&format!("pair={}", asset_pair_name)));

        // get today's opening price
        let data = get_http(url).await?;
        let exchange_rate = extract_response(&data).ok_or(Error::InvalidResponse)?.parse::<f64>()?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price: exchange_rate,
        })
    }
}

#[async_trait]
impl PriceFeed for KrakenApi {
    async fn get_price(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<Currency>,
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
            extract_response(&json!({
                "error":[],
                "result": {
                        "XXBTZUSD": {
                                "a":["19141.50000","3","3.000"],
                                "b":["19141.40000","7","7.000"],
                                "c":["19145.00000","0.01022591"],
                                "v":["647.22057875","2415.97751491"],
                                "p":["19105.89558","19068.90458"],
                                "t":[4359,13327],
                                "l":["19028.50000","18860.00000"],
                                "h":["19190.00000","19259.40000"],
                                "o":"19050.00000"
                        }
                    }
                }
            )),
            Some("19050.00000")
        )
    }
}
