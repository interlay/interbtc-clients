pub mod cli;

mod conn;
mod error;
mod retry;
mod rpc;

pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "testing-utils")]
pub mod integration;

use subxt::{
    sp_runtime::{generic::Header, traits::BlakeTwo256, MultiSignature, OpaqueExtrinsic},
    subxt, Config, ExtrinsicExtraData, StorageEntry,
};

pub use error::Error;
pub use primitives::CurrencyInfo;
pub use retry::{notify_retry, RetryPolicy};
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

pub const RELAY_CHAIN_CURRENCY: CurrencyId = CurrencyId::DOT;
pub const RELAY_CHAIN_WRAPPED_CURRENCY: CurrencyId = CurrencyId::KBTC;

pub const BTC_RELAY_MODULE: &str = "BTCRelay";
pub const ISSUE_MODULE: &str = "Issue";
pub const REDEEM_MODULE: &str = "Redeem";
pub const RELAY_MODULE: &str = "Relay";
pub const SECURITY_MODULE: &str = "Security";

pub const STABLE_BITCOIN_CONFIRMATIONS: &str = "StableBitcoinConfirmations";
pub const STABLE_PARACHAIN_CONFIRMATIONS: &str = "StableParachainConfirmations";

// TODO: possibly substitute CurrencyId, VaultId, H256Le
#[cfg_attr(
    feature = "use-parachain-metadata",
    subxt(
        runtime_metadata_path = "metadata-parachain.scale",
        generated_type_derives = "Debug, Eq, PartialEq, Ord, PartialOrd, Clone"
    )
)]
#[cfg_attr(
    not(feature = "use-parachain-metadata"),
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
        id if id == RichCurrencyId::KSM.symbol() => Ok(CurrencyId::KSM),
        id if id == RichCurrencyId::DOT.symbol() => Ok(CurrencyId::DOT),
        _ => Err(Error::InvalidCurrency),
    }
}

pub fn parse_wrapped_currency(src: &str) -> Result<CurrencyId, Error> {
    match src.to_uppercase().as_str() {
        id if id == RichCurrencyId::KBTC.symbol() => Ok(CurrencyId::KBTC),
        id if id == RichCurrencyId::INTERBTC.symbol() => Ok(CurrencyId::INTERBTC),
        _ => Err(Error::InvalidCurrency),
    }
}
