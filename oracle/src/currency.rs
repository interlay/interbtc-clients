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

pub trait CurrencyInfo<Currency> {
    fn name(&self, id: &Currency) -> Result<String, Error>;
    fn symbol(&self, id: &Currency) -> Result<String, Error>;
    fn decimals(&self, id: &Currency) -> Result<u32, Error>;
}

pub type Currency = String;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CurrencyPair<Currency> {
    /// This is the currency to **buy** - one unit.
    /// Also known as the "transaction" currency.
    pub base: Currency,
    /// This is the currency to **sell**.
    /// Used to determine the value of the base currency.
    /// Also known as the "counter" currency.
    pub quote: Currency,
}

impl fmt::Display for CurrencyPair<Currency> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.base, self.quote)
    }
}

impl<Currency> From<(Currency, Currency)> for CurrencyPair<Currency> {
    fn from((base, quote): (Currency, Currency)) -> Self {
        CurrencyPair { base, quote }
    }
}

impl<Currency: PartialEq> CurrencyPair<Currency> {
    pub fn contains(&self, currency: &Currency) -> bool {
        &self.base == currency || &self.quote == currency
    }

    pub fn has_shared(&self, currency_pair: &Self) -> bool {
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
pub struct CurrencyPairAndPrice<Currency> {
    pub pair: CurrencyPair<Currency>,
    /// Indicates how much of the quote currency is needed to
    /// buy one unit of the base currency.
    ///
    /// ## Example
    /// The quotation BTC/USD = 19037.96 means that 1 BTC can
    /// be exchanged for $19037.96 USD. In this case, BTC is the
    /// base currency and USD is the quote (counter) currency.
    ///
    /// NOTE: this stores the whole unit (i.e. BTC not satoshi)
    pub price: f64,
}

impl fmt::Display for CurrencyPairAndPrice<Currency> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.pair, self.price)
    }
}

impl<Currency: PartialEq + Ord + ToString> CurrencyPairAndPrice<Currency> {
    pub fn invert(self) -> Self {
        Self {
            pair: self.pair.invert(),
            price: self.price.invert(),
        }
    }

    /// Calculate the price for the smallest unit of the base currency.
    ///
    /// ## Example
    /// BTC/DOT = 3081
    /// 1 BTC = 3081 DOT
    /// 1 * 10**8 Satoshi = 3081 * 10**10 Planck
    /// 1 Satoshi = 3081 * 10**2 Planck
    /// 308100 = 3081 * (10**10 / 10**8) = 3081 * 10**2
    pub fn exchange_rate(&self, currency_store: &CurrencyStore<Currency>) -> Result<FixedU128, Error> {
        FixedU128::from_float(self.price)
            .checked_mul(
                &FixedU128::checked_from_rational(
                    10_u128.pow(currency_store.decimals(&self.pair.quote)?),
                    10_u128.pow(currency_store.decimals(&self.pair.base)?),
                )
                .ok_or(Error::InvalidExchangeRate)?,
            )
            .ok_or(Error::InvalidExchangeRate)
    }

    /// Combines two currency pairs with a common element.
    ///
    /// ## Example
    /// BTC/USD * USD/DOT = BTC/DOT
    /// BTC/USD * DOT/USD = BTC/DOT
    /// BTC/USD * BTC/DOT = USD/DOT
    /// BTC/USD * DOT/BTC = USD/DOT
    pub fn reduce(self, other: Self) -> Self {
        let (left, right) = if self.pair.quote == other.pair.quote {
            // quote is same so invert other
            (self, other.invert())
        } else if self.pair.base == other.pair.base {
            // base is same so invert self
            (self.invert(), other)
        } else if self.pair.base == other.pair.quote {
            // base is the same as quote so invert both
            (self.invert(), other.invert())
        } else {
            (self, other)
        };

        Self {
            pair: CurrencyPair {
                base: left.pair.base,
                quote: right.pair.quote,
            },
            price: left.price * right.price,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::CurrencyConfig;

    use super::*;

    #[test]
    fn should_invert_currency_pair_and_price() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "BTC",
                    quote: "DOT"
                },
                price: 2333.0,
            }
            .invert(),
            CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "DOT",
                    quote: "BTC"
                },
                price: 0.0004286326618088298,
            }
        );
    }

    macro_rules! assert_reduce {
        (
            ($left_base:tt / $left_quote:tt @ $left_price:tt)
            *
            ($right_base:tt / $right_quote:tt @ $right_price:tt)
            =
            ($base:tt / $quote:tt @ $price:tt)
        ) => {{
            assert_eq!(
                CurrencyPairAndPrice {
                    pair: CurrencyPair {
                        base: $left_base,
                        quote: $left_quote
                    },
                    price: $left_price,
                }
                .reduce(CurrencyPairAndPrice {
                    pair: CurrencyPair {
                        base: $right_base,
                        quote: $right_quote
                    },
                    price: $right_price,
                }),
                CurrencyPairAndPrice {
                    pair: CurrencyPair {
                        base: $base,
                        quote: $quote
                    },
                    price: $price,
                }
            );
        }};
    }

    #[test]
    fn should_reduce_currencies() {
        // BTC/USD * USD/DOT = BTC/DOT
        assert_reduce!(("BTC" / "USD" @ 19184.24) * ("USD" / "DOT" @ 0.16071505) = ("BTC" / "DOT" @ 3083.1960908120004));

        // BTC/USD * DOT/USD = BTC/DOT
        assert_reduce!(("BTC" / "USD" @ 19184.24) * ("DOT" / "USD" @ 6.23) = ("BTC" / "DOT" @ 3079.332263242376));

        // BTC/USD * BTC/DOT = USD/DOT
        assert_reduce!(("BTC" / "USD" @ 19184.24) * ("BTC" / "DOT" @ 3081.0) = ("USD" / "DOT" @ 0.1606005763063848));

        // BTC/USD * DOT/BTC = USD/DOT
        assert_reduce!(("BTC" / "USD" @ 19184.24) * ("DOT" / "BTC" @ 0.00032457) = ("USD" / "DOT" @ 0.16060054900429147));
    }

    #[test]
    fn should_reduce_currencies_same() {
        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "KSM",
                    quote: "USD"
                },
                price: 42.73,
            }
            .reduce(CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "KSM",
                    quote: "USD"
                },
                price: 42.73,
            }),
            CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "KSM",
                    quote: "KSM"
                },
                price: 1.0,
            }
        );
    }

    #[test]
    fn should_calculate_exchange_rate() {
        let mut currency_store = CurrencyStore::new();
        currency_store.insert(
            "BTC",
            CurrencyConfig {
                name: format!("Bitcoin"),
                decimals: 8,
            },
        );
        currency_store.insert(
            "KSM",
            CurrencyConfig {
                name: format!("Kusama"),
                decimals: 12,
            },
        );

        assert_eq!(
            CurrencyPairAndPrice {
                pair: CurrencyPair {
                    base: "BTC",
                    quote: "KSM"
                },
                price: 453.4139805666768,
            }
            .exchange_rate(&currency_store)
            .unwrap(),
            FixedU128::from_inner(4534139805666767667200000)
        );
    }
}
