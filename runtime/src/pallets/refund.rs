use super::Core;
use crate::RefundRequest;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use serde::Serialize;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Refund: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct RequestRefundEvent<T: Refund> {
    pub refund_id: T::H256,
    pub refundee: T::AccountId,
    pub amount_polka_btc: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub btc_address: T::BtcAddress,
    pub issue_id: T::H256,
    pub fee: T::PolkaBTC,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteRefundCall<T: Refund> {
    pub refund_id: T::H256,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct ExecuteRefundEvent<T: Refund> {
    pub refund_id: T::H256,
    pub refundee: T::AccountId,
    pub vault_id: T::AccountId,
    pub amount: T::PolkaBTC,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RefundRequestsStore<T: Refund> {
    #[store(returns = RefundRequest<T::AccountId, T::PolkaBTC>)]
    pub _runtime: PhantomData<T>,
    pub refund_id: T::H256,
}
