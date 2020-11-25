use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
pub use module_bitcoin::types::H256Le;
pub use module_issue::IssueRequest;
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
    pub amount: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub btc_address: T::H160,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteIssueCall<T: Issue> {
    pub issue_id: T::H256,
    pub tx_id: H256Le,
    pub tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode, Serialize)]
pub struct ExecuteIssueEvent<T: Issue> {
    pub issue_id: T::H256,
    pub requester: T::AccountId,
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
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssuePeriodStore<T: Issue> {
    #[store(returns = u32)]
    pub _runtime: PhantomData<T>,
}
