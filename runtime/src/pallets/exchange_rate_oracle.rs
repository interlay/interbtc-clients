use super::Core;
use crate::timestamp::Timestamp;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use primitives::oracle::Key as OracleKey;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Oracle: Core + Timestamp {}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct AggregateStore<T: Oracle> {
    #[store(returns = T::UnsignedFixedPoint)]
    pub _runtime: PhantomData<T>,
    pub key: OracleKey,
}

/// Maximum delay for the exchange rate to be used
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct MaxDelayStore<T: Oracle> {
    #[store(returns = T::Moment)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct InsertAuthorizedOracleCall<T: Oracle> {
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct FeedValuesCall<T: Oracle> {
    pub _runtime: PhantomData<T>,
    pub values: Vec<(OracleKey, T::UnsignedFixedPoint)>,
}

#[derive(Clone, Debug, PartialEq, Event, Decode)]
pub struct FeedValuesEvent<T: Oracle> {
    pub account_id: T::AccountId,
    pub values: Vec<(OracleKey, T::UnsignedFixedPoint)>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct RawValuesUpdatedStore<'a, T: Oracle> {
    #[store(returns = bool)]
    pub _runtime: PhantomData<T>,
    pub key: &'a OracleKey,
}
