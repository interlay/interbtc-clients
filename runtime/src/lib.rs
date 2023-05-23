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

use codec::{Decode, Encode};
use std::marker::PhantomData;
use subxt::{
    ext::sp_runtime::{generic::Header, traits::BlakeTwo256, MultiSignature},
    subxt,
    tx::PolkadotExtrinsicParams,
    Config,
};

pub use addr::PartialAddress;
pub use assets::{AssetRegistry, LendingAssets, RuntimeCurrencyInfo, TryFromSymbol};
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
pub use std::collections::btree_set::BTreeSet;
use std::time::Duration;
pub use subxt::ext::sp_core::{self, crypto::Ss58Codec, sr25519::Pair};
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

// TODO: possibly substitute CurrencyId, VaultId, H256Le
#[cfg_attr(
    feature = "parachain-metadata-interlay",
    subxt(
        runtime_metadata_path = "metadata-parachain-interlay.scale",
        derive_for_all_types = "Clone",
        derive_for_type(type = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(type = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            type = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(type = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
    )
)]
#[cfg_attr(
    feature = "parachain-metadata-kintsugi",
    subxt(
        runtime_metadata_path = "metadata-parachain-kintsugi.scale",
        derive_for_all_types = "Clone",
        derive_for_type(type = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(type = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            type = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(type = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
    )
)]
#[cfg_attr(
    feature = "parachain-metadata-interlay-testnet",
    subxt(
        runtime_metadata_path = "metadata-parachain-interlay-testnet.scale",
        derive_for_all_types = "Clone",
        derive_for_type(type = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(type = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            type = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(type = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
    )
)]
#[cfg_attr(
    feature = "parachain-metadata-kintsugi-testnet",
    subxt(
        runtime_metadata_path = "metadata-parachain-kintsugi-testnet.scale",
        derive_for_all_types = "Clone",
        derive_for_type(type = "security::types::ErrorCode", derive = "Eq, PartialEq, Ord, PartialOrd"),
        derive_for_type(type = "interbtc_primitives::issue::IssueRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::redeem::RedeemRequestStatus", derive = "Eq, PartialEq"),
        derive_for_type(
            type = "interbtc_primitives::replace::ReplaceRequestStatus",
            derive = "Eq, PartialEq"
        ),
        derive_for_type(type = "interbtc_primitives::VaultId", derive = "Eq, PartialEq"),
        derive_for_type(type = "interbtc_primitives::VaultCurrencyPair", derive = "Eq, PartialEq"),
    )
)]
pub mod metadata {
    #[subxt(substitute_type = "BTreeSet")]
    use crate::BTreeSet;

    #[subxt(substitute_type = "primitive_types::H256")]
    use crate::H256;

    #[subxt(substitute_type = "primitive_types::U256")]
    use crate::U256;

    #[subxt(substitute_type = "primitive_types::H160")]
    use crate::H160;

    #[subxt(substitute_type = "sp_core::crypto::AccountId32")]
    use crate::AccountId;

    #[subxt(substitute_type = "sp_arithmetic::fixed_point::FixedU128")]
    use crate::FixedU128;

    #[subxt(substitute_type = "sp_arithmetic::per_things::Permill")]
    use crate::Ratio;

    #[subxt(substitute_type = "bitcoin::address::Address")]
    use crate::BtcAddress;

    #[subxt(substitute_type = "interbtc_primitives::CurrencyId")]
    use crate::CurrencyId;

    #[subxt(substitute_type = "frame_support::traits::misc::WrapperKeepOpaque")]
    use crate::WrapperKeepOpaque;

    #[subxt(substitute_type = "bitcoin::types::BlockHeader")]
    use ::module_bitcoin::types::BlockHeader;

    #[subxt(substitute_type = "bitcoin::merkle::MerkleProof")]
    use ::module_bitcoin::merkle::MerkleProof;

    #[subxt(substitute_type = "bitcoin::types::Transaction")]
    use ::module_bitcoin::types::Transaction;
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Default, Clone, Decode, Encode)]
pub struct WrapperKeepOpaque<T> {
    data: Vec<u8>,
    _phantom: PhantomData<T>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InterBtcRuntime;

impl Config for InterBtcRuntime {
    type Index = Index;
    type BlockNumber = BlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Address = Self::AccountId;
    type Header = Header<Self::BlockNumber, BlakeTwo256>;
    type Signature = MultiSignature;
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
