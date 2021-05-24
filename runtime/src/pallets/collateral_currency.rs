use super::Core;
use codec::Decode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event};

#[module]
pub trait CollateralCurrency: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct LockEvent<T: CollateralCurrency> {
    pub account_id: T::AccountId,
    pub balance: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ReleaseEvent<T: CollateralCurrency> {
    pub account_id: T::AccountId,
    pub balance: T::Balance,
}
