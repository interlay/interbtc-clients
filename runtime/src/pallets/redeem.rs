use super::Core;
use crate::RedeemRequest;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use serde::Serialize;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Redeem: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestRedeemCall<T: Redeem> {
    #[codec(compact)]
    pub amount: T::Wrapped,
    pub btc_address: T::BtcAddress,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct RequestRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub amount: T::Wrapped,
    pub fee: T::Wrapped,
    pub premium: T::Collateral,
    pub vault_id: T::AccountId,
    pub user_btc_address: T::BtcAddress,
    pub transfer_fee: T::Wrapped,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteRedeemCall<T: Redeem> {
    pub redeem_id: T::H256,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct ExecuteRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub amount: T::Wrapped,
    pub fee: T::Wrapped,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelRedeemCall<T: Redeem> {
    pub redeem_id: T::H256,
    pub reimburse: bool,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct CancelRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub vault_id: T::AccountId,
    pub slashing_amount: T::Collateral,
    pub reimburse: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RedeemRequestsStore<T: Redeem> {
    #[store(returns = RedeemRequest<T::AccountId, T::BlockNumber, T::Wrapped, T::Collateral>)]
    pub _runtime: PhantomData<T>,
    pub redeem_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RedeemPeriodStore<T: Redeem> {
    #[store(returns = T::BlockNumber)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetRedeemPeriodCall<T: Redeem> {
    pub period: T::BlockNumber,
    pub _runtime: PhantomData<T>,
}
