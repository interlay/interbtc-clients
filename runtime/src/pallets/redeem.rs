use core::marker::PhantomData;
pub use module_bitcoin::types::H256Le;
use parity_scale_codec::{Codec, Decode, Encode, EncodeLike};
pub use sp_core::{H160, H256};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Call, Event};

#[module]
pub trait Redeem: System {
    type Balance: Codec + EncodeLike + Member + Default;
    type BTCBalance: Codec + EncodeLike + Member + Default;
    type DOT: Codec + EncodeLike + Member + Default;
    type PolkaBTC: Codec + EncodeLike + Member + Default;
    type H256: Codec + EncodeLike + Member + Default;
    type H160: Codec + EncodeLike + Member + Default;
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestRedeemCall<T: Redeem> {
    pub amount_polka_btc: T::PolkaBTC,
    pub btc_address: H160,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestRedeemEvent<T: Redeem> {
    pub redeem_id: H256,
    pub redeemer: T::AccountId,
    pub amount_polka_btc: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub btc_address: H160,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteRedeemCall<T: Redeem> {
    pub redeem_id: H256,
    pub tx_id: H256Le,
    pub tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteRedeemEvent<T: Redeem> {
    pub redeem_id: H256,
    pub redeemer: T::AccountId,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelRedeemCall<T: Redeem> {
    pub redeem_id: H256,
    pub reimburse: bool,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelRedeemEvent<T: Redeem> {
    pub redeem_id: H256,
    pub redeemer: T::AccountId,
}
