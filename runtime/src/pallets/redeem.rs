use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event};

#[module]
pub trait Redeem: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestRedeemCall<T: Redeem> {
    pub amount_polka_btc: T::PolkaBTC,
    pub btc_address: T::H160,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub amount_polka_btc: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub btc_address: T::H160,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteRedeemCall<T: Redeem> {
    pub redeem_id: T::H256,
    pub tx_id: T::H256Le,
    pub tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelRedeemCall<T: Redeem> {
    pub redeem_id: T::H256,
    pub reimburse: bool,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
}
