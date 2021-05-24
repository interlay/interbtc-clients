use super::Core;
use codec::Decode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event};

#[module]
pub trait WrappedCurrency: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct MintEvent<T: WrappedCurrency> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct LockEvent<T: WrappedCurrency> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct BurnEvent<T: WrappedCurrency> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}
