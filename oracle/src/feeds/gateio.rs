use super::{get_http, PriceFeed};
use crate::{config::CurrencyStore, currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;
use serde_json::Value;

#[derive(Parser, Debug, Clone)]
pub struct GateIoCli {
    /// Fetch the exchange rate from gate.io
    #[clap(long)]
    gateio_url: Option<Url>,
}

pub struct GateIoApi {
    url: Url,
}

impl Default for GateIoApi {
    fn default() -> Self {
        Self {
            url: Url::parse("https://api.gateio.ws/api/v4").unwrap(),
        }
    }
}

fn extract_response<'a>(value: &'a Value) -> Option<&'a str> {
    value.get(0)?.get("last")?.as_str()
}

impl GateIoApi {
    pub fn from_opts(opts: GateIoCli) -> Option<Self> {
        opts.gateio_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<Currency>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        // https://www.gate.io/docs/developers/apiv4/en/
        let mut url = self.url.clone();
        url.set_path(&format!("{}/spot/tickers", url.path()));
        url.set_query(Some(&format!(
            "currency_pair={}_{}",
            currency_store.symbol(&currency_pair.base)?,
            currency_store.symbol(&currency_pair.quote)?,
        )));

        let data = get_http(url).await?;
        let exchange_rate = extract_response(&data).ok_or(Error::InvalidResponse)?.parse::<f64>()?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price: exchange_rate,
        })
    }
}

#[async_trait]
impl PriceFeed for GateIoApi {
    async fn get_price(
        &self,
        currency_pair: CurrencyPair<Currency>,
        currency_store: &CurrencyStore<Currency>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        self.get_exchange_rate(currency_pair, currency_store).await
    }
}
