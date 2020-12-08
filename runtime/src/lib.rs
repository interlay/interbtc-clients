pub mod cli;
mod error;
pub mod pallets;
mod rpc;

#[cfg(test)]
mod tests;

pub use btc_relay::{
    BitcoinBlockHeight, BlockBuilder, BtcAddress, Formattable, H256Le, RawBlockHeader,
    RichBlockHeader,
};
pub use error::{Error, XtError};
use pallets::*;
pub use rpc::{
    historic_event_types, AccountId, BtcRelayPallet, BtcTxFeesPerByte, DotBalancesPallet,
    ExchangeRateOraclePallet, IssuePallet, PolkaBtcIssueRequest, PolkaBtcProvider,
    PolkaBtcRedeemRequest, PolkaBtcReplaceRequest, PolkaBtcStatusUpdate, PolkaBtcVault,
    RedeemPallet, ReplacePallet, SecurityPallet, StakedRelayerPallet, TimestampPallet, UtilFuncs,
    VaultRegistryPallet,
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
use substrate_subxt::{balances, extrinsic::DefaultExtra, sudo, system, Runtime};

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
    type u64 = u64;
    type u128 = u128;
    type Balance = Balance;
    type DOT = Balance;
    type PolkaBTC = Balance;
    type BTCBalance = Balance;
    type RichBlockHeader = RichBlockHeader;
    type H256Le = H256Le;
    type H160 = H160;
    type H256 = H256;
    type BtcAddress = BtcAddress;
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

impl frame_system::System for PolkaBtcRuntime {}

impl redeem::Redeem for PolkaBtcRuntime {}

impl replace::Replace for PolkaBtcRuntime {}

impl sudo::Sudo for PolkaBtcRuntime {}
