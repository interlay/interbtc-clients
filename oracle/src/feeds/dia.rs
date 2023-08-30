#![allow(clippy::single_char_pattern)]
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
            url: Url::parse("https://api.diadata.org/v1/").unwrap(),
        }
    }
}

fn extract_response(value: Value) -> Option<f64> {
    value.get("Price")?.as_f64()
}

fn set_token_path(base: &mut Url, token_path: &str) {
    let base_path = base.path().trim_end_matches("/");
    let new_path = format!("{base_path}/assetQuotation/{token_path}");
    base.set_path(&new_path);
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
        _currency_store: &CurrencyStore<String>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        if currency_pair.quote.symbol() != "USD" {
            return Err(Error::InvalidDiaSymbol);
        }
        let token_path = currency_pair.base.path().ok_or(Error::InvalidDiaSymbol)?;

        // https://docs.diadata.org/documentation/api-1/api-endpoints#asset-quotation
        let mut url = self.url.clone();

        set_token_path(&mut url, &token_path);
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
    fn build_url_works() {
        let expected_url = "https://api.diadata.org/v1/assetQuotation/some_asset";

        let mut with_trailing_slash = Url::parse("https://api.diadata.org/v1/").unwrap();
        set_token_path(&mut with_trailing_slash, "some_asset");

        assert_eq!(with_trailing_slash.to_string(), expected_url);

        let mut without_trailing_slash = Url::parse("https://api.diadata.org/v1").unwrap();
        set_token_path(&mut without_trailing_slash, "some_asset");
        assert_eq!(without_trailing_slash.to_string(), expected_url);
    }

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
