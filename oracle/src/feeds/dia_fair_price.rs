#![allow(clippy::single_char_pattern)]
use super::{get_http, PriceFeed};
use crate::{config::CurrencyStore, currency::*, Error};
use async_trait::async_trait;
use clap::Parser;
use reqwest::Url;
use serde_json::Value;

#[derive(Parser, Debug, Clone)]
pub struct DiaFairPriceCli {
    /// Fetch the exchange rate from Dia xLSD feed
    #[clap(long)]
    dia_fair_price_url: Option<Url>,
}

pub struct DiaFairPriceApi {
    url: Url,
}

impl Default for DiaFairPriceApi {
    fn default() -> Self {
        Self {
            url: Url::parse("https://api.diadata.org/xlsd/").unwrap(),
        }
    }
}

fn extract_response(value: Value, alias: &str, index: usize) -> Option<f64> {
    let entry = value.get(index)?;

    if matches!(entry.get("Token")?.as_str(), Some(token) if token.to_uppercase() != alias) {
        // expected index position does not match token
        return None;
    }

    entry
        .get("FairPrice")?
        .as_f64()
        .and_then(|x| if x.is_normal() { Some(1.0 / x) } else { None })
}

impl DiaFairPriceApi {
    pub fn from_opts(opts: DiaFairPriceCli) -> Option<Self> {
        opts.dia_fair_price_url.map(Self::new)
    }

    pub fn new(url: Url) -> Self {
        Self { url }
    }

    async fn get_exchange_rate(
        &self,
        currency_pair: CurrencyPair<Currency>,
        _currency_store: &CurrencyStore<String>,
    ) -> Result<CurrencyPairAndPrice<Currency>, Error> {
        if currency_pair.base.symbol() != "USD" {
            return Err(Error::InvalidDiaSymbol);
        }
        let extension = currency_pair.quote.ext().ok_or(Error::InvalidDiaSymbol)?;
        // this allows us to override the expected token name
        // which is helpful when using the xlsd feed of a wrapped token
        // but we want to submit the currency as the underlying (e.g. KBTC -> BTC)
        let alias = extension.alias.unwrap_or(currency_pair.quote.symbol());
        let index = extension.index.ok_or(Error::NoFairPriceIndex)?;

        let url = self.url.clone();
        let data = get_http(url).await?;

        let price = extract_response(data, alias.as_str(), index).ok_or(Error::InvalidResponse)?;

        Ok(CurrencyPairAndPrice {
            pair: currency_pair,
            price,
        })
    }
}

#[async_trait]
impl PriceFeed for DiaFairPriceApi {
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
                json!([
                    {
                        "Token": "KBTC",
                        "FairPrice": 27418.406434486784,
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": 27418.406434486784,
                        "Issuer": "Interlay"
                    },
                    {
                        "Token": "vKSM",
                        "FairPrice": 24.611983172737727,
                        "BaseAssetSymbol": "KSM",
                        "BaseAssetPrice": 19.827745134261495,
                        "Issuer": "Bifrost"
                    }
                ]),
                "KBTC",
                0
            ),
            Some(1.0 / 27418.406434486784)
        )
    }
}
