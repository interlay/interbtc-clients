pub mod cli;
mod error;
pub mod pallets;
mod rpc;
mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "testing-utils")]
pub mod integration;

pub use btc_relay::{
    BitcoinBlockHeight, BlockBuilder, BtcAddress, BtcPublicKey, Formattable, H256Le,
    RawBlockHeader, RichBlockHeader,
};
pub use error::{Error, XtError};
use pallets::*;
pub use rpc::{
    BtcRelayPallet, BtcTxFeesPerByte, DotBalancesPallet, ExchangeRateOraclePallet, FeePallet,
    IssuePallet, PolkaBtcProvider, RedeemPallet, RefundPallet, ReplacePallet, SecurityPallet,
    StakedRelayerPallet, TimestampPallet, UtilFuncs, VaultRegistryPallet,
};
pub use security::{ErrorCode, StatusCode};
pub use sp_arithmetic::{traits as FixedPointTraits, FixedI128, FixedPointNumber, FixedU128};
use sp_core::{H160, H256};
pub use sp_runtime;
use sp_runtime::{
    generic::Header,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature, OpaqueExtrinsic,
};
use std::collections::BTreeSet;
pub use substrate_subxt;
use substrate_subxt::register_default_type_sizes;
use substrate_subxt::system::SystemEventTypeRegistry;
use substrate_subxt::EventTypeRegistry;
use substrate_subxt::{balances, extrinsic::DefaultExtra, sudo, system, Runtime};
pub use types::*;
use vault_registry::VaultStatus;

use parachain::primitives::{Id as ParaId, RelayChainBlockNumber};
use xcm::v0::{Error as XcmError, NetworkId};

pub const MINIMUM_STAKE: u128 = 100;
pub const TX_FEES: u128 = 2000000000;
pub const PLANCK_PER_DOT: u128 = 10000000000;

pub type Balance = u128;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolkaBtcRuntime;

impl Runtime for PolkaBtcRuntime {
    type Signature = MultiSignature;
    type Extra = DefaultExtra<Self>;

    fn register_type_sizes(registry: &mut EventTypeRegistry<Self>) {
        registry.with_core();
        registry.with_system();
        register_default_type_sizes(registry);
    }
}

pub type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;

// TODO: use types from actual runtime
impl system::System for PolkaBtcRuntime {
    type Index = u32;
    type BlockNumber = u32;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Address = Self::AccountId;
    type Header = Header<Self::BlockNumber, BlakeTwo256>;
    type Extrinsic = OpaqueExtrinsic;
    type AccountData = balances::AccountData<Balance>;
}

impl pallets::Core for PolkaBtcRuntime {
    type Balance = Balance;
    type DOT = Balance;
    type PolkaBTC = Balance;
    type BTCBalance = Balance;
    type RichBlockHeader = RichBlockHeader<AccountId>;
    type H256Le = H256Le;
    type H160 = H160;
    type H256 = H256;
    type BtcAddress = BtcAddress;
    type BtcPublicKey = BtcPublicKey;
    type ErrorCode = ErrorCode;
    type ErrorCodes = BTreeSet<ErrorCode>;
    type StatusCode = StatusCode;
    type StatusUpdateId = u64;
    type SignedFixedPoint = FixedI128;
    type UnsignedFixedPoint = FixedU128;
    type VaultStatus = VaultStatus;

    // cumulus / polkadot types
    type XcmError = XcmError;
    type NetworkId = NetworkId;
    type RelayChainBlockNumber = RelayChainBlockNumber;
    type ParaId = ParaId;
}

impl balances::Balances for PolkaBtcRuntime {
    type Balance = Balance;
}

impl btc_relay::BTCRelay for PolkaBtcRuntime {}

impl security::Security for PolkaBtcRuntime {}

impl staked_relayers::StakedRelayers for PolkaBtcRuntime {}

impl collateral::Collateral for PolkaBtcRuntime {}

impl vault_registry::VaultRegistry for PolkaBtcRuntime {}

impl timestamp::Timestamp for PolkaBtcRuntime {
    type Moment = u64;
}

impl exchange_rate_oracle::ExchangeRateOracle for PolkaBtcRuntime {}

impl balances_dot::DOT for PolkaBtcRuntime {
    type Balance = Balance;
}

impl issue::Issue for PolkaBtcRuntime {}

impl frame_system::System for PolkaBtcRuntime {}

impl redeem::Redeem for PolkaBtcRuntime {}

impl replace::Replace for PolkaBtcRuntime {}

impl refund::Refund for PolkaBtcRuntime {}

impl sudo::Sudo for PolkaBtcRuntime {}

impl fee::Fee for PolkaBtcRuntime {}

impl sla::Sla for PolkaBtcRuntime {}

impl treasury::Treasury for PolkaBtcRuntime {}
