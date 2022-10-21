use super::{get_http, PriceFeed};
use crate::{config::CurrencyStore, currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;
use serde_json::Value;

#[derive(Parser, Debug, Clone)]
pub struct DiaCli {
    /// Fetch the exchange rate from Dia
    #[clap(long)]
    dia_url: Option<Url>,
}

pub struct DiaApi {
    url: Url,
}

impl Default for DiaApi {
    fn default() -> Self {
        Self {
            url: Url::parse("https://api.diadata.org/v1/assetQuotation/").unwrap(),
        }
    }
}

fn extract_response(value: Value) -> Option<f64> {
    value.get("Price")?.as_f64()
}

impl DiaApi {
    pub fn from_opts(opts: DiaCli) -> Option<Self> {
        opts.dia_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(
        &self,
        currency_pair: CurrencyPair<Currency>,
        _currency_store: &CurrencyStore<Currency>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        if currency_pair.base != "USD" {
            return Err(Error::InvalidDiaSymbol);
        }
        let token_path = currency_pair
            .quote
            .split("=")
            .skip(1)
            .next()
            .ok_or(Error::InvalidDiaSymbol)?;

        // https://docs.diadata.org/documentation/api-1/api-endpoints#asset-quotation

        let mut url = self.url.clone();
        url.set_path(&format!("{}/{}", url.path(), token_path));
        let data = get_http(url).await?;
        let price = extract_response(data).ok_or(Error::InvalidResponse)?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price,
        })
    }
}

#[async_trait]
impl PriceFeed for DiaApi {
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
            extract_response(json!({
                "Symbol": "stDOT",
                "Name": "Liquid staked DOT",
                "Address": "0xFA36Fe1dA08C89eC72Ea1F0143a35bFd5DAea108",
                "Blockchain": "Moonbeam",
                "Price": 5.842649511778436,
                "PriceYesterday": 6.198461622083585,
                "VolumeYesterdayUSD": 1715.460868,
                "Time": "2022-10-21T07:35:24Z",
                "Source": "diadata.org"
            })),
            Some(5.842649511778436)
        )
    }
}
