mod error;
pub mod pallets;
mod rpc;

#[cfg(test)]
mod tests;

pub use btc_relay::{
    Address, BitcoinBlockHeight, BlockBuilder, Formattable, H256Le, RawBlockHeader, RichBlockHeader,
};
pub use error::{Error, XtError};
use pallets::*;
pub use rpc::{
    AccountId, BtcRelayPallet, DotBalancesPallet, ExchangeRateOraclePallet, IssuePallet,
    PolkaBtcProvider, PolkaBtcStatusUpdate, PolkaBtcVault, RedeemPallet, ReplacePallet,
    SecurityPallet, StakedRelayerPallet, TimestampPallet, VaultRegistryPallet,
};
pub use security::{ErrorCode, StatusCode};
use sp_core::{H160, H256};
use sp_runtime::{
    generic::Header,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature, OpaqueExtrinsic,
};
use std::collections::BTreeSet;
pub use substrate_subxt;
use substrate_subxt::{balances, extrinsic::DefaultExtra, system, Runtime};

pub const MINIMUM_STAKE: u64 = 100;

pub type Balance = u128;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolkaBtcRuntime;

impl Runtime for PolkaBtcRuntime {
    type Signature = MultiSignature;
    type Extra = DefaultExtra<Self>;
}

// TODO: use types from actual runtime
impl system::System for PolkaBtcRuntime {
    type Index = u32;
    type BlockNumber = u32;
    type Hash = sp_core::H256;
    type Hashing = BlakeTwo256;
    type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
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
    type H256Le = H256Le;
    type u128 = u128;
    type RichBlockHeader = RichBlockHeader;
    type H160 = H160;
    type H256 = H256;
    type ErrorCode = ErrorCode;
    type ErrorCodes = BTreeSet<ErrorCode>;
    type StatusCode = StatusCode;
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

impl redeem::Redeem for PolkaBtcRuntime {}

impl replace::Replace for PolkaBtcRuntime {}
