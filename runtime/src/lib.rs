pub mod cli;
pub mod pallets;

mod conn;
mod error;
mod retry;
mod rpc;
mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "testing-utils")]
pub mod integration;

pub use error::{Error, SubxtError};
pub use pallets::*;
pub use primitives::{oracle::Key as OracleKey, CurrencyId, CurrencyInfo};
pub use retry::{notify_retry, RetryPolicy};
pub use rpc::{
    BtcRelayPallet, CollateralBalancesPallet, FeePallet, InterBtcParachain, IssuePallet, OraclePallet, RedeemPallet,
    RefundPallet, RelayPallet, ReplacePallet, SecurityPallet, TimestampPallet, UtilFuncs, VaultRegistryPallet,
};
pub use sp_arithmetic::{traits as FixedPointTraits, FixedI128, FixedPointNumber, FixedU128};
pub use sp_runtime;
pub use substrate_subxt;
pub use types::*;

use sp_core::crypto::Ss58Codec;
use sp_runtime::{
    generic::Header,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature, OpaqueExtrinsic,
};
use std::collections::BTreeSet;
use substrate_subxt::{
    balances, extrinsic::DefaultExtra, register_default_type_sizes, sudo, system, system::SystemEventTypeRegistry,
    EventTypeRegistry, Runtime,
};

// cumulus / polkadot types
use polkadot_parachain::primitives::{Id as ParaId, RelayChainBlockNumber};
use xcm::v0::{Error as XcmError, NetworkId};

pub const TX_FEES: u128 = 2000000000;

pub const MILLISECS_PER_BLOCK: u64 = 6000;

// These time units are defined in number of blocks.
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;

pub const RELAY_CHAIN_WRAPPED_CURRENCY: CurrencyId = CurrencyId::KBTC;

pub type Balance = u128;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InterBtcRuntime;

impl Runtime for InterBtcRuntime {
    type Signature = MultiSignature;
    type Extra = DefaultExtra<Self>;

    fn register_type_sizes(registry: &mut EventTypeRegistry<Self>) {
        // TODO: resolve bug in metadata generation
        registry.register_type_size::<FixedU128>("T::UnsignedFixedPoint");
        registry.with_core();
        registry.with_system();
        register_default_type_sizes(registry);
    }
}

pub type Index = u32;

/// An index to a block.
pub type BlockNumber = u32;

/// Some way of identifying an account on the chain.
pub type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
pub type VaultId = primitives::VaultId<AccountId, CurrencyId>;

// TODO: use types from actual runtime
impl system::System for InterBtcRuntime {
    type Index = Index;
    type BlockNumber = BlockNumber;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Address = Self::AccountId;
    type Header = Header<Self::BlockNumber, BlakeTwo256>;
    type Extrinsic = OpaqueExtrinsic;
    type AccountData = balances::AccountData<Balance>;
}

impl pallets::Core for InterBtcRuntime {
    type Balance = Balance;
    type Collateral = Balance;
    type Wrapped = Balance;
    type RichBlockHeader = InterBtcRichBlockHeader;
    type H256Le = H256Le;
    type H160 = H160;
    type H256 = H256;
    type BtcAddress = BtcAddress;
    type BtcPublicKey = BtcPublicKey;
    type ErrorCode = ErrorCode;
    type ErrorCodeSet = BTreeSet<ErrorCode>;
    type StatusCode = StatusCode;
    type SignedFixedPoint = FixedI128;
    type UnsignedFixedPoint = FixedU128;
    type VaultStatus = VaultStatus;
    type RedeemRequestStatus = RedeemRequestStatus;
    type CurrencyId = CurrencyId;
    type OracleKey = OracleKey;
    type VaultId = VaultId;

    // cumulus / polkadot types
    type XcmError = XcmError;
    type NetworkId = NetworkId;
    type RelayChainBlockNumber = RelayChainBlockNumber;
    type ParaId = ParaId;
}

impl balances::Balances for InterBtcRuntime {
    type Balance = Balance;
}

impl btc_relay::BTCRelay for InterBtcRuntime {}

impl security::Security for InterBtcRuntime {}

impl relay::Relay for InterBtcRuntime {}

impl vault_registry::VaultRegistry for InterBtcRuntime {}

impl timestamp::Timestamp for InterBtcRuntime {
    type Moment = u64;
}

impl exchange_rate_oracle::Oracle for InterBtcRuntime {}

impl tokens::Tokens for InterBtcRuntime {}

impl issue::Issue for InterBtcRuntime {}

impl frame_system::System for InterBtcRuntime {}

impl redeem::Redeem for InterBtcRuntime {}

impl replace::Replace for InterBtcRuntime {}

impl refund::Refund for InterBtcRuntime {}

impl sudo::Sudo for InterBtcRuntime {}

impl fee::Fee for InterBtcRuntime {}

impl sla::Sla for InterBtcRuntime {}

impl utility::Utility for InterBtcRuntime {}

pub const BTC_RELAY_MODULE: &str = "BTCRelay";
pub const ISSUE_MODULE: &str = "Issue";
pub const REDEEM_MODULE: &str = "Redeem";
pub const RELAY_MODULE: &str = "Relay";
pub const SECURITY_MODULE: &str = "Security";

pub const STABLE_BITCOIN_CONFIRMATIONS: &str = "StableBitcoinConfirmations";
pub const STABLE_PARACHAIN_CONFIRMATIONS: &str = "StableParachainConfirmations";

pub const DUPLICATE_BLOCK_ERROR: &str = "DuplicateBlock";
pub const INVALID_CHAIN_ID_ERROR: &str = "InvalidChainID";
pub const ISSUE_COMPLETED_ERROR: &str = "IssueCompleted";
pub const COMMIT_PERIOD_EXPIRED_ERROR: &str = "CommitPeriodExpired";
pub const PARACHAIN_SHUTDOWN_ERROR: &str = "ParachainShutdown";
pub const VALID_REFUND_TRANSACTION_ERROR: &str = "ValidRefundTransaction";

pub fn parse_collateral_currency(src: &str) -> Result<CurrencyId, Error> {
    match src.to_uppercase().as_str() {
        id if id == CurrencyId::KSM.symbol() => Ok(CurrencyId::KSM),
        id if id == CurrencyId::DOT.symbol() => Ok(CurrencyId::DOT),
        _ => Err(Error::InvalidCurrency),
    }
}

pub trait VaultIdFormatter {
    fn pretty_printed(&self) -> String;
}

impl VaultIdFormatter for VaultId {
    fn pretty_printed(&self) -> String {
        format!(
            "{}[{}->{}]",
            self.account_id.to_ss58check(),
            self.currencies.collateral.name(),
            self.currencies.wrapped.name()
        )
    }
}
