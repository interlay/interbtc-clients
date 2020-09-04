use module_bitcoin::types::H256Le;
use sp_core::U256;
use sp_runtime::{
    generic::Header,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiSignature, OpaqueExtrinsic,
};
use substrate_subxt::{balances, extrinsic::DefaultExtra, system, Runtime};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PolkaBTC;

impl Runtime for PolkaBTC {
    type Signature = MultiSignature;
    type Extra = DefaultExtra<Self>;
}

impl system::System for PolkaBTC {
    type Index = u32;
    type BlockNumber = u32;
    type Hash = sp_core::H256;
    type Hashing = BlakeTwo256;
    type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
    type Address = Self::AccountId;
    type Header = Header<Self::BlockNumber, BlakeTwo256>;
    type Extrinsic = OpaqueExtrinsic;
    // type AccountData = balances::AccountData<<Self as balances::Balances>::Balance>;
    type AccountData = balances::AccountData<u128>;
}

impl balances::Balances for PolkaBTC {
    type Balance = u128;
}

pub mod pallet_btc_relay;
pub mod pallet_collateral;
pub mod pallet_security;
pub mod pallet_staked_relayers;

pub use pallet_security::{ErrorCode, StatusCode};

impl pallet_btc_relay::BTCRelay for PolkaBTC {
    type H256Le = H256Le;
}

impl pallet_security::Security for PolkaBTC {}

impl pallet_staked_relayers::StakedRelayers for PolkaBTC {
    type DOT = u128;
    type U256 = U256;
    type StatusCode = StatusCode;
    type ErrorCode = ErrorCode;
}

impl pallet_collateral::Collateral for PolkaBTC {
    type DOT = u128;
}
