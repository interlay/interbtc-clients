use crate::{currency::*, error::ConfigError, feeds::FeedName, Error};
use serde::Deserialize;
use std::{collections::BTreeMap, convert::TryFrom};

#[derive(Deserialize, Debug, Clone)]
pub struct OracleConfig {
    pub currencies: BTreeMap<Currency, CurrencyConfig>,
    pub prices: Vec<PriceConfig>,
}

pub type CurrencyStore = BTreeMap<Currency, CurrencyConfig>;

#[derive(Deserialize, Debug, Clone)]
pub struct CurrencyConfig {
    pub name: String,
    pub decimals: u32,
}

impl CurrencyInfo for CurrencyStore {
    fn name(&self, id: &Currency) -> Result<String, Error> {
        self.get(id)
            .ok_or(Error::InvalidCurrency)
            .map(|asset_config| asset_config.name.clone())
    }

    fn symbol(&self, id: &Currency) -> Result<String, Error> {
        Ok(id.clone())
    }

    fn decimals(&self, id: &Currency) -> Result<u32, Error> {
        self.get(id)
            .ok_or(Error::InvalidCurrency)
            .map(|asset_config| asset_config.decimals.clone())
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct PriceConfig {
    pub pair: CurrencyPair,
    pub feeds: BTreeMap<FeedName, Vec<CurrencyPair>>,
}

impl PriceConfig {
    pub fn validate(&self) -> Result<(), Error> {
        for (name, path) in &self.feeds {
            let end = &match &path.first() {
                Some(currency_pair) if currency_pair.contains(&self.pair.base) => Ok(self.pair.quote.clone()),
                Some(currency_pair) if currency_pair.contains(&self.pair.quote) => Ok(self.pair.base.clone()),
                _ => Err(Error::InvalidConfig(
                    name.clone(),
                    self.pair.clone(),
                    ConfigError::NoStart,
                )),
            }?;

            match &path.last() {
                Some(CurrencyPair { base, .. }) if base == end => Ok(()),
                Some(CurrencyPair { quote, .. }) if quote == end => Ok(()),
                _ => Err(Error::InvalidConfig(
                    name.clone(),
                    self.pair.clone(),
                    ConfigError::NoEnd,
                )),
            }?;

            for [left, right] in path.windows(2).flat_map(<&[CurrencyPair; 2]>::try_from) {
                if !left.has_shared(right) {
                    return Err(Error::InvalidConfig(
                        name.clone(),
                        self.pair.clone(),
                        ConfigError::NoPath(left.clone(), right.clone()),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_valid {
        ($pair:expr => [$($path:expr),*]) => {{
            PriceConfig {
                pair: $pair,
                feeds: vec![(FeedName::Kraken, vec![$($path),*])].into_iter().collect()
            }
            .validate().expect("Config is valid")
        }};
    }

    macro_rules! assert_invalid {
        ($pair:expr => [$($path:expr),*], $err:pat) => {{
            let result = PriceConfig {
                pair: $pair,
                feeds: vec![(FeedName::Kraken, vec![$($path),*])].into_iter().collect()
            }
            .validate();
            assert!(
                matches!(
                    result,
                    Err(Error::InvalidConfig(FeedName::Kraken, _, $err))
                ),
                "Actual result: {:?}", result
            )
        }};
    }

    #[test]
    fn should_accept_valid_paths() {
        assert_valid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: BTC, quote: KSM }
            ]
        );

        assert_valid!(
            CurrencyPair { base: DOT, quote: INTR } => [
                CurrencyPair { base: USD, quote: DOT },
                CurrencyPair { base: USD, quote: INTR }
            ]
        );
    }

    #[test]
    fn should_reject_invalid_paths() {
        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [],
            ConfigError::NoStart
        );

        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: USD, quote: DOT }
            ],
            ConfigError::NoStart
        );

        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: BTC, quote: BTC }
            ],
            ConfigError::NoEnd
        );

        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: BTC, quote: KINT }
            ],
            ConfigError::NoEnd
        );

        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: BTC, quote: USDT },
                CurrencyPair { base: USDT, quote: KINT }
            ],
            ConfigError::NoEnd
        );

        assert_invalid!(
            CurrencyPair { base: BTC, quote: KSM } => [
                CurrencyPair { base: KSM, quote: USD },
                CurrencyPair { base: KINT, quote: USD },
                CurrencyPair { base: DOT, quote: BTC }
            ],
            ConfigError::NoPath(
                CurrencyPair { base: KINT, quote: USD },
                CurrencyPair { base: DOT, quote: BTC }
            )
        );
    }
}
