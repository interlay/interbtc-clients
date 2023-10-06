use crate::{types::*, AssetMetadata, Error};
use lazy_static::lazy_static;
use primitives::{CurrencyId, CurrencyInfo};
use std::{
    collections::BTreeMap,
    sync::{Mutex, MutexGuard},
};

lazy_static! {
    // NOTE: restrict access to the lock to ensure that no async code yields while holding the mutex
    static ref ASSET_REGISTRY: Mutex<AssetRegistry> = Mutex::new(AssetRegistry::default());
}

/// The symbol of Lend Tokens is the symbol of their underlying currency,
/// prefixed by `Q`. Example: `QDOT` is the `DOT` lend token symbol.
const LEND_TOKEN_SYMBOL_PREFIX: char = 'Q';

#[derive(Debug, Clone, Default)]
pub struct AssetRegistry {
    symbol_lookup: BTreeMap<String, u32>,
    metadata_lookup: BTreeMap<u32, AssetMetadata>,
}

impl AssetRegistry {
    /// Fetch the global, mutable singleton
    fn global() -> Result<MutexGuard<'static, Self>, Error> {
        ASSET_REGISTRY.lock().map_err(|_| Error::CannotOpenAssetRegistry)
    }

    fn inner_insert(&mut self, foreign_asset_id: u32, asset_metadata: AssetMetadata) -> Result<(), Error> {
        let asset_name = String::from_utf8(asset_metadata.symbol.clone())
            .map_err(|_| Error::InvalidCurrency)?
            .to_uppercase();
        log::info!("Found asset: {}", asset_name);
        self.symbol_lookup.insert(asset_name, foreign_asset_id);
        self.metadata_lookup.insert(foreign_asset_id, asset_metadata);
        Ok(())
    }

    pub fn insert(foreign_asset_id: u32, asset_metadata: AssetMetadata) -> Result<(), Error> {
        let mut asset_registry = Self::global()?;
        asset_registry.inner_insert(foreign_asset_id, asset_metadata)?;
        Ok(())
    }

    pub(crate) fn extend(assets: Vec<(u32, AssetMetadata)>) -> Result<(), Error> {
        let mut asset_registry = Self::global()?;
        for (foreign_asset_id, asset_metadata) in assets {
            // TODO: check for duplicates?
            asset_registry.inner_insert(foreign_asset_id, asset_metadata)?;
        }
        Ok(())
    }

    /// Fetch the currency for a ticker symbol
    pub fn get_foreign_asset_by_symbol(symbol: String) -> Result<CurrencyId, Error> {
        Self::global()?
            .symbol_lookup
            .get(&symbol)
            .map(|foreign_asset_id| CurrencyId::ForeignAsset(*foreign_asset_id))
            .ok_or(Error::AssetNotFound)
    }

    /// Fetch the asset metadata for a foreign asset
    pub fn get_asset_metadata_by_id(foreign_asset_id: u32) -> Result<AssetMetadata, Error> {
        Self::global()?
            .metadata_lookup
            .get(&foreign_asset_id)
            .cloned()
            .ok_or(Error::AssetNotFound)
    }
}

lazy_static! {
    // NOTE: restrict access to the lock to ensure that no async code yields while holding the mutex
    static ref LENDING_ASSETS: Mutex<LendingAssets> = Mutex::new(LendingAssets::default());
}

#[derive(Debug, Clone, Default)]
pub struct LendingAssets {
    underlying_to_lend_token: BTreeMap<CurrencyId, CurrencyId>,
    lend_token_to_underlying: BTreeMap<CurrencyId, CurrencyId>,
}

impl LendingAssets {
    /// Fetch the global, mutable singleton
    fn global() -> Result<MutexGuard<'static, Self>, Error> {
        LENDING_ASSETS.lock().map_err(|_| Error::CannotOpenAssetRegistry)
    }

    pub fn insert(underlying_id: CurrencyId, lend_token_id: CurrencyId) -> Result<(), Error> {
        log::info!(
            "Found loans market: {:?}, with lend token: {:?}",
            underlying_id,
            lend_token_id
        );
        let mut lending_assets = Self::global()?;
        lending_assets
            .underlying_to_lend_token
            .insert(underlying_id, lend_token_id);
        lending_assets
            .lend_token_to_underlying
            .insert(lend_token_id, underlying_id);
        Ok(())
    }

    pub(crate) fn extend(assets: Vec<(CurrencyId, CurrencyId)>) -> Result<(), Error> {
        for (underlying_id, lend_token_id) in assets {
            // TODO: check for duplicates?
            Self::insert(underlying_id, lend_token_id)?;
        }
        Ok(())
    }

    /// Fetch the lend token id associated with an underlying currency
    pub fn get_lend_token_id(underlying_id: CurrencyId) -> Result<CurrencyId, Error> {
        Self::global()?
            .underlying_to_lend_token
            .get(&underlying_id)
            .cloned()
            .ok_or(Error::AssetNotFound)
    }

    /// Fetch the underlying id associated with a lend token currency
    pub fn get_underlying_id(lend_token_id: CurrencyId) -> Result<CurrencyId, Error> {
        Self::global()?
            .lend_token_to_underlying
            .get(&lend_token_id)
            .cloned()
            .ok_or(Error::AssetNotFound)
    }
}

/// Convert a ticker symbol into a `CurrencyId` at runtime
pub trait TryFromSymbol: Sized {
    fn try_from_symbol(symbol: String) -> Result<Self, Error>;
    fn from_lend_token_symbol(symbol: &str) -> Option<Self>;
}

impl TryFromSymbol for CurrencyId {
    fn try_from_symbol(symbol: String) -> Result<Self, Error> {
        let uppercase_symbol = symbol.to_uppercase();
        // try hardcoded currencies first
        match uppercase_symbol.as_str() {
            id if id == DOT.symbol() => Ok(Token(DOT)),
            id if id == IBTC.symbol() => Ok(Token(IBTC)),
            id if id == INTR.symbol() => Ok(Token(INTR)),
            id if id == KSM.symbol() => Ok(Token(KSM)),
            id if id == KBTC.symbol() => Ok(Token(KBTC)),
            id if id == KINT.symbol() => Ok(Token(KINT)),
            id if let Some(currency_id) = Self::from_lend_token_symbol(id) =>
                Ok(currency_id),
            _ => AssetRegistry::get_foreign_asset_by_symbol(uppercase_symbol),
        }
    }

    fn from_lend_token_symbol(symbol: &str) -> Option<Self> {
        let uppercase_symbol = symbol.to_uppercase();
        // Does the first character match the lend token prefix?
        if uppercase_symbol.as_str().starts_with(LEND_TOKEN_SYMBOL_PREFIX) {
            return Self::try_from_symbol(uppercase_symbol[1..].to_string())
                .ok()
                .and_then(|underlying_id| LendingAssets::get_lend_token_id(underlying_id).ok());
        }
        None
    }
}

/// Fallible operations on currencies
pub trait RuntimeCurrencyInfo {
    fn symbol(&self) -> Result<String, Error>;
    fn decimals(&self) -> Result<u32, Error>;
    fn one(&self) -> Result<u128, Error>;
    fn coingecko_id(&self) -> Result<String, Error>;
}

impl RuntimeCurrencyInfo for CurrencyId {
    fn symbol(&self) -> Result<String, Error> {
        match self {
            CurrencyId::Token(token_symbol) => Ok(token_symbol.symbol().to_string()),
            CurrencyId::ForeignAsset(foreign_asset_id) => AssetRegistry::get_asset_metadata_by_id(*foreign_asset_id)
                .and_then(|asset_metadata| {
                    String::from_utf8(asset_metadata.symbol).map_err(|_| Error::InvalidCurrency)
                }),
            CurrencyId::LendToken(id) => {
                let underlying_currency = LendingAssets::get_underlying_id(CurrencyId::LendToken(*id))?;
                Ok(format!("{}{}", LEND_TOKEN_SYMBOL_PREFIX, underlying_currency.symbol()?))
            }
            _ => Err(Error::TokenUnsupported),
        }
    }

    fn decimals(&self) -> Result<u32, Error> {
        match self {
            CurrencyId::Token(token_symbol) => Ok(token_symbol.decimals().into()),
            CurrencyId::ForeignAsset(foreign_asset_id) => {
                AssetRegistry::get_asset_metadata_by_id(*foreign_asset_id).map(|asset_metadata| asset_metadata.decimals)
            }
            CurrencyId::LendToken(id) => {
                let underlying_currency = LendingAssets::get_underlying_id(CurrencyId::LendToken(*id))?;
                underlying_currency.decimals()
            }
            _ => Err(Error::TokenUnsupported),
        }
    }

    fn one(&self) -> Result<u128, Error> {
        let decimals = self.decimals()?;
        Ok(10u128.pow(decimals))
    }

    fn coingecko_id(&self) -> Result<String, Error> {
        match self {
            CurrencyId::Token(token_symbol) => Ok(token_symbol.name().to_string().to_lowercase()),
            CurrencyId::ForeignAsset(foreign_asset_id) => AssetRegistry::get_asset_metadata_by_id(*foreign_asset_id)
                .and_then(|asset_metadata| {
                    String::from_utf8(asset_metadata.additional.coingecko_id).map_err(|_| Error::InvalidCurrency)
                }),
            _ => Err(Error::TokenUnsupported),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::runtime_types::interbtc_primitives::CustomMetadata;

    #[test]
    fn should_store_metadata() -> Result<(), Error> {
        let expected_asset_metadata = AssetMetadata {
            decimals: 10,
            location: None,
            name: b"Asset 1".to_vec(),
            symbol: b"AST1".to_vec(),
            existential_deposit: 0,
            additional: CustomMetadata {
                fee_per_second: 0,
                coingecko_id: vec![],
            },
        };
        AssetRegistry::global()?.inner_insert(0, expected_asset_metadata.clone())?;

        let actual_asset_metadata = AssetRegistry::get_asset_metadata_by_id(0)?;
        assert_eq!(expected_asset_metadata.name, actual_asset_metadata.name);
        assert_eq!(expected_asset_metadata.symbol, actual_asset_metadata.symbol);

        Ok(())
    }

    #[test]
    fn should_convert_token_symbol() -> Result<(), Error> {
        assert_eq!(CurrencyId::try_from_symbol("DOT".to_string())?, Token(DOT));
        assert_eq!(CurrencyId::try_from_symbol("INTR".to_string())?, Token(INTR));
        assert_eq!(CurrencyId::try_from_symbol("IBTC".to_string())?, Token(IBTC));
        Ok(())
    }

    #[test]
    fn should_get_runtime_info_for_token_symbol() -> Result<(), Error> {
        assert_eq!(Token(DOT).symbol()?, "DOT");
        assert_eq!(Token(DOT).decimals()?, 10);
        assert_eq!(Token(DOT).one()?, 10000000000);
        assert_eq!(Token(IBTC).one()?, 100000000);
        Ok(())
    }

    #[test]
    fn should_convert_foreign_asset() -> Result<(), Error> {
        AssetRegistry::global()?.inner_insert(
            0,
            AssetMetadata {
                decimals: 10,
                location: None,
                name: b"Asset 1".to_vec(),
                symbol: b"AST1".to_vec(),
                existential_deposit: 0,
                additional: CustomMetadata {
                    fee_per_second: 0,
                    coingecko_id: vec![],
                },
            },
        )?;
        assert_eq!(CurrencyId::try_from_symbol("AST1".to_string())?, ForeignAsset(0));
        Ok(())
    }

    #[test]
    fn should_get_runtime_info_for_foreign_asset() -> Result<(), Error> {
        AssetRegistry::global()?.inner_insert(
            0,
            AssetMetadata {
                decimals: 10,
                location: None,
                name: b"Asset 1".to_vec(),
                symbol: b"AST1".to_vec(),
                existential_deposit: 0,
                additional: CustomMetadata {
                    fee_per_second: 0,
                    coingecko_id: vec![],
                },
            },
        )?;

        assert_eq!(ForeignAsset(0).symbol()?, "AST1");
        assert_eq!(ForeignAsset(0).decimals()?, 10);
        assert_eq!(ForeignAsset(0).one()?, 10000000000);
        Ok(())
    }
}
