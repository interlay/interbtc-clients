use super::Core;
use crate::RedeemRequest;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use primitives::VaultId;
use serde::Serialize;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Redeem: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestRedeemCall<'a, T: Redeem> {
    #[codec(compact)]
    pub amount: T::Wrapped,
    pub btc_address: T::BtcAddress,
    pub vault_id: &'a VaultId<T::AccountId, T::CurrencyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct RequestRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub amount: T::Wrapped,
    pub fee: T::Wrapped,
    pub premium: T::Collateral,
    pub vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub user_btc_address: T::BtcAddress,
    pub transfer_fee: T::Wrapped,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteRedeemCall<'a, T: Redeem> {
    pub redeem_id: T::H256,
    pub merkle_proof: &'a [u8],
    pub raw_tx: &'a [u8],
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct ExecuteRedeemEvent<T: Redeem> {
    pub redeem_id: T::H256,
    pub redeemer: T::AccountId,
    pub vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub amount: T::Wrapped,
    pub fee: T::Wrapped,
    pub transfer_fee_btc: T::Wrapped,
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
    pub vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub slashing_amount: T::Collateral,
    pub reimburse: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RedeemRequestsStore<T: Redeem> {
    #[store(returns = RedeemRequest<T::AccountId, T::BlockNumber, T::Balance, T::CurrencyId>)]
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
