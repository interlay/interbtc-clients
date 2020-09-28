mod error;
mod pallets;
mod rpc;

#[cfg(test)]
mod tests;

pub use btc_relay::{BitcoinBlockHeight, H256Le, RawBlockHeader, RichBlockHeader};
pub use error::Error;
use pallets::*;
pub use rpc::{
    AccountId, ExchangeRateOraclePallet, IssuePallet, PolkaBtcProvider, PolkaBtcStatusUpdate,
    PolkaBtcVault, RedeemPallet, SecurityPallet, StakedRelayerPallet, TimestampPallet,
};
pub use security::{ErrorCode, StatusCode};
use sp_core::U256;
use sp_core::{H160, H256};
use sp_runtime::{
    generic::Header,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature, OpaqueExtrinsic,
};
use std::collections::BTreeSet;
use substrate_subxt::{balances, extrinsic::DefaultExtra, system, Runtime};

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
    type AccountData = balances::AccountData<u128>;
}

impl balances::Balances for PolkaBtcRuntime {
    type Balance = u128;
}

impl btc_relay::BTCRelay for PolkaBtcRuntime {
    type H256Le = H256Le;
    type RichBlockHeader = RichBlockHeader;
}

impl security::Security for PolkaBtcRuntime {
    type ErrorCodes = BTreeSet<ErrorCode>;
}

impl staked_relayers::StakedRelayers for PolkaBtcRuntime {
    type DOT = u128;
    type U256 = U256;
    type H256Le = H256Le;
    type StatusCode = StatusCode;
    type ErrorCode = ErrorCode;
}

impl collateral::Collateral for PolkaBtcRuntime {
    type DOT = u128;
}

impl vault_registry::VaultRegistry for PolkaBtcRuntime {
    type Balance = u128;
    type DOT = u128;
    type PolkaBTC = u128;
}

impl timestamp::Timestamp for PolkaBtcRuntime {
    type Moment = u64;
}

impl exchange_rate_oracle::ExchangeRateOracle for PolkaBtcRuntime {
    type u128 = u128;
    type StatusCode = StatusCode;
    type ErrorCode = ErrorCode;
}

impl balances_dot::DOT for PolkaBtcRuntime {
    type Balance = u128;
}

impl issue::Issue for PolkaBtcRuntime {
    type Balance = u128;
    type BTCBalance = u128;
    type DOT = u128;
    type PolkaBTC = u128;
    type H160 = H160;
    type H256 = H256;
}

impl redeem::Redeem for PolkaBtcRuntime {
    type Balance = u128;
    type BTCBalance = u128;
    type DOT = u128;
    type PolkaBTC = u128;
    type H160 = H160;
    type H256 = H256;
}
