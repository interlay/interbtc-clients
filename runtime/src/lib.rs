pub mod cli;

mod conn;
mod error;
mod retry;
mod rpc;

pub mod types;

#[cfg(test)]
mod tests;

#[cfg(all(feature = "testing-utils", feature = "standalone-metadata"))]
pub mod integration;

use codec::{Decode, Encode};
use sp_std::marker::PhantomData;
use subxt::{
    sp_runtime::{generic::Header, traits::BlakeTwo256, MultiSignature, OpaqueExtrinsic},
    subxt, Config, ExtrinsicExtraData, StorageEntry,
};

pub use error::Error;
pub use primitives::CurrencyInfo;
pub use retry::{notify_retry, RetryPolicy};
#[cfg(all(
    feature = "testing-utils",
    any(feature = "standalone-metadata", feature = "parachain-metadata-testnet")
))]
pub use rpc::SudoPallet;
pub use rpc::{
    BtcRelayPallet, CollateralBalancesPallet, FeePallet, InterBtcParachain, IssuePallet, OraclePallet, RedeemPallet,
    RefundPallet, RelayPallet, ReplacePallet, SecurityPallet, TimestampPallet, UtilFuncs, VaultRegistryPallet,
};

pub use sp_arithmetic::{traits as FixedPointTraits, FixedI128, FixedPointNumber, FixedU128};
pub use subxt::{
    sp_core::{crypto::Ss58Codec, sr25519::Pair},
    Error as SubxtError, PairSigner, Signer,
};
pub use types::*;

pub const TX_FEES: u128 = 2000000000;
pub const MILLISECS_PER_BLOCK: u64 = 6000;

pub const RELAY_CHAIN_CURRENCY: CurrencyId = Token(DOT);
pub const RELAY_CHAIN_WRAPPED_CURRENCY: CurrencyId = Token(KBTC);

pub const BTC_RELAY_MODULE: &str = "BTCRelay";
pub const ISSUE_MODULE: &str = "Issue";
pub const REDEEM_MODULE: &str = "Redeem";
pub const RELAY_MODULE: &str = "Relay";
pub const SECURITY_MODULE: &str = "Security";

pub const STABLE_BITCOIN_CONFIRMATIONS: &str = "StableBitcoinConfirmations";
pub const STABLE_PARACHAIN_CONFIRMATIONS: &str = "StableParachainConfirmations";

// TODO: possibly substitute CurrencyId, VaultId, H256Le
#[cfg_attr(
    feature = "parachain-metadata-kintsugi",
    subxt(
        runtime_metadata_path = "metadata-parachain-kintsugi.scale",
        generated_type_derives = "Debug, Eq, PartialEq, Ord, PartialOrd, Clone"
    )
)]
#[cfg_attr(
    feature = "parachain-metadata-testnet",
    subxt(
        runtime_metadata_path = "metadata-parachain-testnet.scale",
        generated_type_derives = "Debug, Eq, PartialEq, Ord, PartialOrd, Clone"
    )
)]
#[cfg_attr(
    feature = "standalone-metadata",
    subxt(
        runtime_metadata_path = "metadata-standalone.scale",
        generated_type_derives = "Debug, Eq, PartialEq, Ord, PartialOrd, Clone"
    )
)]
pub mod metadata {
    #[subxt(substitute_type = "BTreeSet")]
    use sp_std::collections::btree_set::BTreeSet;

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

    #[subxt(substitute_type = "bitcoin::address::Address")]
    use crate::BtcAddress;

    #[subxt(substitute_type = "interbtc_primitives::CurrencyId")]
    use crate::CurrencyId;

    #[subxt(substitute_type = "frame_support::traits::misc::WrapperKeepOpaque")]
    use crate::WrapperKeepOpaque;
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
    type Extrinsic = OpaqueExtrinsic;
    type Signature = MultiSignature;
}

impl ExtrinsicExtraData<InterBtcRuntime> for InterBtcRuntime {
    type AccountData = metadata::system::storage::Account;
    type Extra = subxt::extrinsic::DefaultExtra<Self>;
}

impl From<<InterBtcRuntime as Config>::AccountId> for metadata::system::storage::Account {
    fn from(account_id: <InterBtcRuntime as Config>::AccountId) -> Self {
        Self(account_id)
    }
}

impl subxt::AccountData<InterBtcRuntime> for metadata::system::storage::Account {
    fn nonce(result: &<Self as StorageEntry>::Value) -> <InterBtcRuntime as Config>::Index {
        result.nonce
    }
    fn storage_entry(account_id: <InterBtcRuntime as Config>::AccountId) -> Self {
        Self(account_id)
    }
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
        id if id == INTERBTC.symbol() => Ok(Token(INTERBTC)),
        _ => Err(Error::InvalidCurrency),
    }
}
