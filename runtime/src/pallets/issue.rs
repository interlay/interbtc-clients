use super::{Core, CoreEventsDecoder};
use crate::{BtcAddress, BtcPublicKey};
use core::marker::PhantomData;
pub use module_bitcoin::types::H256Le;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Issue: Core {}

// TODO: use the type exported by module_issue when dependency conflicts are resolved.
// Due to a known bug in serde we need to specify how u128 is (de)serialized.
// See https://github.com/paritytech/substrate/issues/4641
#[derive(Encode, Decode, Default, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct IssueRequest<AccountId, BlockNumber, PolkaBTC, DOT> {
    pub vault: AccountId,
    pub opentime: BlockNumber,
    #[serde(bound(deserialize = "DOT: std::str::FromStr"))]
    #[serde(deserialize_with = "deserialize_from_string")]
    #[serde(bound(serialize = "DOT: std::fmt::Display"))]
    #[serde(serialize_with = "serialize_as_string")]
    pub griefing_collateral: DOT,
    #[serde(bound(deserialize = "PolkaBTC: std::str::FromStr"))]
    #[serde(deserialize_with = "deserialize_from_string")]
    #[serde(bound(serialize = "PolkaBTC: std::fmt::Display"))]
    #[serde(serialize_with = "serialize_as_string")]
    pub amount: PolkaBTC,
    #[serde(bound(deserialize = "PolkaBTC: std::str::FromStr"))]
    #[serde(deserialize_with = "deserialize_from_string")]
    #[serde(bound(serialize = "PolkaBTC: std::fmt::Display"))]
    #[serde(serialize_with = "serialize_as_string")]
    pub fee: PolkaBTC,
    pub requester: AccountId,
    pub btc_address: BtcAddress,
    pub btc_public_key: BtcPublicKey,
    pub completed: bool,
    pub cancelled: bool,
}

fn serialize_as_string<S: Serializer, T: std::fmt::Display>(
    t: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&t.to_string())
}

fn deserialize_from_string<'de, D: Deserializer<'de>, T: std::str::FromStr>(
    deserializer: D,
) -> Result<T, D::Error> {
    let s = String::deserialize(deserializer)?;
    s.parse::<T>()
        .map_err(|_| serde::de::Error::custom("Parse from string failed"))
}

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
    pub tx_id: H256Le,
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
