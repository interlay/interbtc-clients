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

fn extract_response(value: Value, alias: &str) -> Option<f64> {
    let entry = value
        .as_array()?
        .into_iter()
        .find(|entry| matches!(entry.get("Token").and_then(|value| value.as_str()), Some(token) if token.to_uppercase() == alias))?;

    // check if necessary variables exist (for resiliency)
    {
        let collateral_ratio = entry.get("Collateralratio")?;
        (!collateral_ratio.get("IssuedToken")?.is_null()).then_some(())?;
        (!collateral_ratio.get("LockedToken")?.is_null()).then_some(())?;
        (!collateral_ratio.get("Ratio")?.is_null()).then_some(())?;

        (!entry.get("BaseAssetPrice")?.is_null()).then_some(())?;
    }

    entry.get("FairPrice")?.as_f64()
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
        if currency_pair.quote.symbol() != "USD" {
            return Err(Error::InvalidDiaSymbol);
        }
        // this allows us to override the expected token name
        // which is helpful when using the xlsd feed of a wrapped token
        // but we want to submit the currency as the underlying (e.g. KBTC -> BTC)
        let alias = currency_pair.base.path().unwrap_or(currency_pair.base.symbol());

        let url = self.url.clone();
        let data = get_http(url).await?;

        let price = extract_response(data, alias.as_str()).ok_or(Error::InvalidResponse)?;

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
                        "FairPrice": 27368.444386909556,
                        "Collateralratio": {
                            "IssuedToken": 5.06295411,
                            "LockedToken": 10.11669883,
                            "Ratio": 1.9981810243980267
                        },
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": 27368.444386909556,
                        "Issuer": "Interlay"
                    },
                    {
                        "Token": "vKSM",
                        "FairPrice": 23.236193861853113,
                        "Collateralratio": {
                            "IssuedToken": 258963.93436582384,
                            "LockedToken": 325404.742440816,
                            "Ratio": 1.2565639429200783
                        },
                        "BaseAssetSymbol": "KSM",
                        "BaseAssetPrice": 18.491851523174745,
                        "Issuer": "Bifrost"
                    }
                ]),
                "KBTC",
            ),
            Some(27368.444386909556)
        )
    }

    #[test]
    fn should_not_extract_missing_response() {
        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 27368.444386909556,
                        "Collateralratio": {
                            "IssuedToken": 61.5231675,
                            "LockedToken": 103.26883812,
                            "Ratio": 1.678535782800845
                        },
                        "BaseAssetSymbol": "BTC",
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );

        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 27368.444386909556,
                        "Collateralratio": {
                            "IssuedToken": 61.5231675,
                            "LockedToken": 103.26883812
                        },
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": 27368.444386909556,
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );

        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 27368.444386909556,
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": 27368.444386909556,
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );
    }

    #[test]
    fn should_not_extract_null_response() {
        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 26227.957995921395,
                        "Collateralratio": {
                            "IssuedToken": null,
                            "LockedToken": null,
                            "Ratio": null
                        },
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": null,
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );

        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 27431.274823315267,
                        "Collateralratio": {
                            "IssuedToken": 61.5231675,
                            "LockedToken": 103.46858575,
                            "Ratio": null
                        },
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": 27431.274823315267,
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );

        assert_eq!(
            extract_response(
                json!([
                    {
                        "Token": "IBTC",
                        "FairPrice": 27431.274823315267,
                        "Collateralratio": {
                            "IssuedToken": 61.5231675,
                            "LockedToken": 103.46858575,
                            "Ratio": 1.681782488686071
                        },
                        "BaseAssetSymbol": "BTC",
                        "BaseAssetPrice": null,
                        "Issuer": "Interlay"
                    }
                ]),
                "IBTC",
            ),
            None
        );
    }
}
