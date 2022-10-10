#![allow(clippy::upper_case_acronyms)]

use crate::Error;
use runtime::{CurrencyId, FixedPointNumber, FixedPointTraits::*, FixedU128, TryFromSymbol};
use serde::{de::Error as _, Deserialize, Deserializer};
use std::{
    convert::TryInto,
    fmt::{self, Debug},
    str::FromStr,
};

pub trait ExchangeRate {
    fn invert(self) -> Self;
}

impl ExchangeRate for f64 {
    fn invert(self) -> Self {
        1.0 / self
    }
}

pub trait CurrencyInfo {
    fn name(&self) -> &str;
    fn symbol(&self) -> &str;
    fn decimals(&self) -> u8;
}

macro_rules! create_currency {
    ($(#[$meta:meta])*
	$vis:vis enum Currency {
        $($(#[$vmeta:meta])* $symbol:ident($name:expr, $deci:literal),)*
    }) => {
		$(#[$meta])*
		$vis enum Currency {
			$($(#[$vmeta])* $symbol,)*
		}

        $(
            #[allow(dead_code)]
            pub const $symbol: Currency = Currency::$symbol;
        )*

		impl CurrencyInfo for Currency {
			fn name(&self) -> &str {
				match self {
					$(Currency::$symbol => $name,)*
				}
			}
			fn symbol(&self) -> &str {
				match self {
					$(Currency::$symbol => stringify!($symbol),)*
				}
			}
			fn decimals(&self) -> u8 {
				match self {
					$(Currency::$symbol => $deci,)*
				}
            }
		}

        impl FromStr for Currency {
            type Err = Error;
            fn from_str(symbol: &str) -> Result<Self, Self::Err> {
                let uppercase_symbol = symbol.to_uppercase();
                // try hardcoded currencies first
                match uppercase_symbol.as_str() {
                    $(stringify!($symbol) => Ok(Currency::$symbol),)*
                    _ => Err(Error::InvalidCurrency),
                }
            }
        }
    }
}

create_currency! {
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[repr(u8)]
    pub enum Currency {
        DOT("Polkadot", 10),
        INTR("Interlay", 10),
        KSM("Kusama", 12),
        KINT("Kintsugi", 12),
        BTC("Bitcoin", 8),
        USDT("Tether", 6),
        USD("United State Dollar", 2),
        // TODO: add alias for exchange id
        AUSD("Acala-Dollar", 12),
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let symbol = String::deserialize(d)?;
        Currency::from_str(&symbol).map_err(D::Error::custom)
    }
}

impl TryInto<CurrencyId> for Currency {
    type Error = Error;
    fn try_into(self) -> Result<CurrencyId, Self::Error> {
        CurrencyId::try_from_symbol(self.symbol().to_string()).map_err(Error::RuntimeError)
    }
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
pub struct CurrencyPair {
    pub base: Currency,
    pub quote: Currency,
}

impl fmt::Display for CurrencyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.base.symbol(), self.quote.symbol())
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

    pub fn exchange_rate(&self) -> Option<FixedU128> {
        FixedU128::from_float(self.price).checked_mul(&FixedU128::checked_from_rational(
            10_u128.pow(self.pair.quote.decimals().into()),
            10_u128.pow(self.pair.base.decimals().into()),
        )?)
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
