#![allow(clippy::too_many_arguments)]
#![feature(if_let_guard)]

pub mod cli;

mod addr;
mod assets;
mod conn;
mod error;
mod retry;
mod rpc;
mod shutdown;

pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "testing-utils")]
pub mod integration;
use subxt::config::SubstrateConfig;
pub mod utils;
pub use addr::PartialAddress;
pub use assets::{AssetRegistry, LendingAssets, RuntimeCurrencyInfo, TryFromSymbol};
use codec::{Decode, Encode};
pub use error::{Error, SubxtError};
pub use primitives::CurrencyInfo;
pub use prometheus;
pub use retry::{notify_retry, RetryPolicy};
#[cfg(feature = "testing-utils")]
pub use rpc::SudoPallet;
pub use rpc::{
    BtcRelayPallet, CollateralBalancesPallet, FeePallet, FeeRateUpdateReceiver, InterBtcParachain, IssuePallet,
    OraclePallet, RedeemPallet, ReplacePallet, SecurityPallet, TimestampPallet, UtilFuncs, VaultRegistryPallet,
    DEFAULT_SPEC_NAME, SS58_PREFIX,
};
pub use shutdown::{ShutdownReceiver, ShutdownSender};
pub use sp_arithmetic::{traits as FixedPointTraits, FixedI128, FixedPointNumber, FixedU128};
pub use sp_core;
pub use std::collections::btree_set::BTreeSet;
use std::{marker::PhantomData, time::Duration};
use subxt::{config::polkadot::PolkadotExtrinsicParams, subxt, Config};
pub use types::*;
pub const TX_FEES: u128 = 2000000000;
pub const MILLISECS_PER_BLOCK: u64 = 12000;
pub const BLOCK_INTERVAL: Duration = Duration::from_millis(MILLISECS_PER_BLOCK);

pub const BTC_RELAY_MODULE: &str = "BTCRelay";
pub const ISSUE_MODULE: &str = "Issue";
pub const SECURITY_MODULE: &str = "Security";
pub const SYSTEM_MODULE: &str = "System";
pub const VAULT_REGISTRY_MODULE: &str = "VaultRegistry";

pub const STABLE_BITCOIN_CONFIRMATIONS: &str = "StableBitcoinConfirmations";
pub const STABLE_PARACHAIN_CONFIRMATIONS: &str = "StableParachainConfirmations";
pub const DISABLE_DIFFICULTY_CHECK: &str = "DisableDifficultyCheck";

// TODO: possibly substitute CurrencyId, VaultId, H256Le
#[cfg_attr(
    feature = "parachain-metadata-interlay",
    subxt(
        runtime_metadata_path = "metadata-parachain-interlay.scale",
        derive_for_all_types = "Clone",
        derive_for_type(path = "bitcoin::address::PublicKey", derive = "Eq, PartialEq"),
        derive_for_type(path = "bitcoin::types::H256Le", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            path = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(path = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(path = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(path = "security::types::StatusCode", derive = "Eq, PartialEq"),
        substitute_type(path = "primitive_types::H256", with = "::subxt::utils::Static<crate::H256>"),
        substitute_type(path = "primitive_types::U256", with = "::subxt::utils::Static<crate::U256>"),
        substitute_type(path = "primitive_types::H160", with = "::subxt::utils::Static<crate::H160>"),
        substitute_type(path = "sp_core::crypto::AccountId32", with = "crate::AccountId"),
        substitute_type(
            path = "sp_arithmetic::fixed_point::FixedU128",
            with = "::subxt::utils::Static<crate::FixedU128>"
        ),
        substitute_type(
            path = "sp_arithmetic::per_things::Permill",
            with = "::subxt::utils::Static<crate::Ratio>"
        ),
        substitute_type(
            path = "bitcoin::address::Address",
            with = "::subxt::utils::Static<crate::BtcAddress>"
        ),
        substitute_type(path = "interbtc_primitives::CurrencyId", with = "crate::CurrencyId"),
        substitute_type(
            path = "frame_support::traits::misc::WrapperKeepOpaque",
            with = "::subxt::utils::Static<crate::WrapperKeepOpaque>"
        ),
        substitute_type(
            path = "bitcoin::types::BlockHeader",
            with = "::subxt::utils::Static<::module_bitcoin::types::BlockHeader>"
        ),
        substitute_type(
            path = "bitcoin::merkle::MerkleProof",
            with = "::subxt::utils::Static<::module_bitcoin::merkle::MerkleProof>"
        ),
        substitute_type(
            path = "bitcoin::types::Transaction",
            with = "::subxt::utils::Static<::module_bitcoin::types::Transaction>"
        ),
    )
)]
#[cfg_attr(
    feature = "parachain-metadata-kintsugi",
    subxt(
        runtime_metadata_path = "metadata-parachain-kintsugi.scale",
        derive_for_all_types = "Clone",
        derive_for_type(path = "bitcoin::address::PublicKey", derive = "Eq, PartialEq"),
        derive_for_type(path = "bitcoin::types::H256Le", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            path = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(path = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
        derive_for_type(path = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(path = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(path = "security::types::StatusCode", derive = "Eq, PartialEq"),
        substitute_type(path = "primitive_types::H256", with = "::subxt::utils::Static<crate::H256>"),
        substitute_type(path = "primitive_types::U256", with = "::subxt::utils::Static<crate::U256>"),
        substitute_type(path = "primitive_types::H160", with = "::subxt::utils::Static<crate::H160>"),
        substitute_type(path = "sp_core::crypto::AccountId32", with = "crate::AccountId"),
        substitute_type(
            path = "sp_arithmetic::fixed_point::FixedU128",
            with = "::subxt::utils::Static<crate::FixedU128>"
        ),
        substitute_type(
            path = "sp_arithmetic::per_things::Permill",
            with = "::subxt::utils::Static<crate::Ratio>"
        ),
        substitute_type(
            path = "bitcoin::address::Address",
            with = "::subxt::utils::Static<crate::BtcAddress>"
        ),
        substitute_type(path = "interbtc_primitives::CurrencyId", with = "crate::CurrencyId"),
        substitute_type(
            path = "frame_support::traits::misc::WrapperKeepOpaque",
            with = "::subxt::utils::Static<crate::WrapperKeepOpaque>"
        ),
        substitute_type(
            path = "bitcoin::types::BlockHeader",
            with = "::subxt::utils::Static<::module_bitcoin::types::BlockHeader>"
        ),
        substitute_type(
            path = "bitcoin::merkle::MerkleProof",
            with = "::subxt::utils::Static<::module_bitcoin::merkle::MerkleProof>"
        ),
        substitute_type(
            path = "bitcoin::types::Transaction",
            with = "::subxt::utils::Static<::module_bitcoin::types::Transaction>"
        ),
    )
)]

pub mod metadata {}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Default, Clone, Decode, Encode)]
pub struct WrapperKeepOpaque<T> {
    data: Vec<u8>,
    _phantom: PhantomData<T>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InterBtcRuntime;

impl Config for InterBtcRuntime {
    type Index = <SubstrateConfig as Config>::Index;
    type Hash = <SubstrateConfig as Config>::Hash;
    type AccountId = AccountId;
    type Address = Self::AccountId;
    type Signature = MultiSignature;
    type Hasher = <SubstrateConfig as Config>::Hasher;
    type Header = <SubstrateConfig as Config>::Header;
    type ExtrinsicParams = PolkadotExtrinsicParams<Self>;
}

pub fn parse_collateral_currency(src: &str) -> Result<CurrencyId, Error> {
    match src.to_uppercase().as_str() {
        id if id == KSM.symbol() => Ok(Token(KSM)),
        id if id == DOT.symbol() => Ok(Token(DOT)),
        x => parse_native_currency(x),
    }
}

pub fn parse_native_currency(src: &str) -> Result<CurrencyId, Error> {
    match src.to_uppercase().as_str() {
        id if id == KINT.symbol() => Ok(Token(KINT)),
        id if id == INTR.symbol() => Ok(Token(INTR)),
        _ => Err(Error::InvalidCurrency),
    }
}

pub fn parse_wrapped_currency(src: &str) -> Result<CurrencyId, Error> {
    match src.to_uppercase().as_str() {
        id if id == KBTC.symbol() => Ok(Token(KBTC)),
        id if id == IBTC.symbol() => Ok(Token(IBTC)),
        _ => Err(Error::InvalidCurrency),
    }
}
