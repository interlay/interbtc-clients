use super::Core;
use crate::IssueRequest;
use core::marker::PhantomData;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Issue: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestIssueCall<T: Issue> {
    pub amount: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct RequestIssueEvent<T: Issue> {
    pub issue_id: T::H256,
    pub requester: T::AccountId,
    pub amount_btc: T::PolkaBTC, //add _btc
    pub fee_polkabtc: T::PolkaBTC,
    pub griefing_collateral: T::DOT,
    pub vault_id: T::AccountId,
    pub vault_btc_address: T::BtcAddress,
    pub vault_public_key: T::BtcPublicKey,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteIssueCall<T: Issue> {
    pub issue_id: T::H256,
    pub tx_id: T::H256Le,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct ExecuteIssueEvent<T: Issue> {
    pub issue_id: T::H256,
    pub requester: T::AccountId,
    pub total_amount: T::PolkaBTC,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelIssueCall<T: Issue> {
    pub issue_id: T::H256,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct CancelIssueEvent<T: Issue> {
    pub issue_id: T::H256,
    pub requester: T::AccountId,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssueRequestsStore<T: Issue> {
    #[store(returns = IssueRequest<T::AccountId, T::BlockNumber, T::PolkaBTC, T::DOT>)]
    pub _runtime: PhantomData<T>,
    pub issue_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssuePeriodStore<T: Issue> {
    #[store(returns = u32)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetIssuePeriodCall<T: Issue> {
    pub period: u32,
    pub _runtime: PhantomData<T>,
}
