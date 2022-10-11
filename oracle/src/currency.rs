#![allow(clippy::upper_case_acronyms)]

use crate::{CurrencyStore, Error};
use runtime::{FixedPointNumber, FixedPointTraits::*, FixedU128};
use serde::Deserialize;
use std::fmt::{self, Debug};

pub trait ExchangeRate {
    fn invert(self) -> Self;
}

impl ExchangeRate for f64 {
    fn invert(self) -> Self {
        1.0 / self
    }
}

pub trait CurrencyInfo {
    fn name(&self, id: &Currency) -> Result<String, Error>;
    fn symbol(&self, id: &Currency) -> Result<String, Error>;
    fn decimals(&self, id: &Currency) -> Result<u32, Error>;
}

pub type Currency = String;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CurrencyPair {
    pub base: Currency,
    pub quote: Currency,
}

impl fmt::Display for CurrencyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.base, self.quote)
    }
}

impl From<(Currency, Currency)> for CurrencyPair {
    fn from((base, quote): (Currency, Currency)) -> Self {
        CurrencyPair { base, quote }
    }
}

impl CurrencyPair {
    pub fn contains(&self, currency: &Currency) -> bool {
        &self.base == currency || &self.quote == currency
    }

    pub fn has_shared(&self, currency_pair: &CurrencyPair) -> bool {
        self.contains(&currency_pair.base) || self.contains(&currency_pair.quote)
    }

    pub fn invert(self) -> Self {
        Self {
            base: self.quote,
            quote: self.base,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CurrencyPairAndPrice {
    pub pair: CurrencyPair,
    pub price: f64,
}

impl fmt::Display for CurrencyPairAndPrice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.pair.to_string(), self.price)
    }
}

impl CurrencyPairAndPrice {
    pub fn invert(self) -> Self {
        Self {
            pair: self.pair.invert(),
            price: self.price.invert(),
        }
    }

    pub fn exchange_rate(&self, currency_store: &CurrencyStore) -> Result<FixedU128, Error> {
        Ok(FixedU128::from_float(self.price)
            .checked_mul(
                &FixedU128::checked_from_rational(
                    10_u128.pow(currency_store.decimals(&self.pair.quote)?.into()),
                    10_u128.pow(currency_store.decimals(&self.pair.base)?.into()),
                )
                .ok_or(Error::InvalidExchangeRate)?,
            )
            .ok_or(Error::InvalidExchangeRate)?)
    }

    pub fn reduce(self, other: Self) -> Self {
        let other = if self.pair.quote == other.pair.quote {
            // quote is same so invert other
            other.invert()
        } else {
            other
        };

        Self {
            pair: CurrencyPair {
                base: self.pair.base,
                quote: other.pair.quote,
            },
            price: self.price * other.price,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_invert_currency_pair_and_price() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: BTC, quote: DOT },
                price: 2333.0,
            }
            .invert(),
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: DOT, quote: BTC },
                price: 0.0004286326618088298,
            }
        );
    }

    #[test]
    fn should_reduce_currencies() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: DOT, quote: USD },
                price: 6.32,
            }
            .reduce(CurrencyPairAndPrice {
                pair: CurrencyPair { base: BTC, quote: USD },
                price: 19718.25,
            }),
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: DOT, quote: BTC },
                price: 0.00032051525870703534,
            }
        );
    }

    #[test]
    fn should_reduce_currencies_same() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: KSM, quote: USD },
                price: 42.73,
            }
            .reduce(CurrencyPairAndPrice {
                pair: CurrencyPair { base: KSM, quote: USD },
                price: 42.73,
            }),
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: KSM, quote: KSM },
                price: 1.0,
            }
        );
    }

    #[test]
    fn should_calculate_exchange_rate() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair { base: BTC, quote: KSM },
                price: 453.4139805666768,
            }
            .exchange_rate(),
            Some(FixedU128::from_inner(4534139805666767667200000))
        );
    }
}
