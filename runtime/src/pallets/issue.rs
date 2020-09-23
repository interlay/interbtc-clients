use core::marker::PhantomData;
use parity_scale_codec::{Codec, Decode, Encode, EncodeLike};
pub use sp_core::{H160, H256};
pub use module_bitcoin::types::H256Le;
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Call, Event};

#[module]
pub trait Issue: System  {
    type Balance: Codec + EncodeLike + Member + Default;
    type DOT: Codec + EncodeLike + Member + Default;
    type PolkaBTC: Codec + EncodeLike + Member + Default;
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestIssueCall<T: Issue> {
    pub amount: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestIssueEvent<T: Issue> {
    pub issue_id: H256,
    pub requester: T::AccountId,
    pub amount: T::PolkaBTC,
    pub vault_id: T::AccountId,
    pub btc_address: H160,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteIssueCall<T: Issue> {
    pub issue_id: H256,
    pub tx_id: H256Le,
    pub tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteIssueEvent<T: Issue> {
    pub issue_id: H256,
    pub requester: T::AccountId,
    pub vault_id: T::AccountId,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelIssueCall<T: Issue> {
    pub requester: T::AccountId,
    pub issue_id: H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelIssueEvent<T: Issue> {
    pub issue_id: H256,
    pub requester: T::AccountId,
}
