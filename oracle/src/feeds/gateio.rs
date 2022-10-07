use super::{get_http, PriceFeed};
use crate::{currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;

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

impl GateIoApi {
    pub fn from_opts(opts: GateIoCli) -> Option<Self> {
        opts.gateio_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(&self, currency_pair: CurrencyPair) -> Result<CurrencyPairAndPrice, Error> {
        // https://www.gate.io/docs/developers/apiv4/en/
        let mut url = self.url.clone();
        url.set_path(&format!("{}/spot/tickers", url.path()));
        url.set_query(Some(&format!(
            "currency_pair={}_{}",
            currency_pair.base.symbol(),
            currency_pair.quote.symbol()
        )));

        let exchange_rate = get_http(url)
            .await?
            .get(0)
            .ok_or(Error::InvalidResponse)?
            .get("last")
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
impl PriceFeed for GateIoApi {
    async fn get_price(&self, currency_pair: CurrencyPair) -> Result<CurrencyPairAndPrice, Error> {
        self.get_exchange_rate(currency_pair).await
    }
}
