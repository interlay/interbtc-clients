use super::{Core, CoreEventsDecoder};
use parity_scale_codec::Decode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event};

#[module]
pub trait Collateral: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct LockCollateralEvent<T: Collateral> {
    pub account_id: T::AccountId,
    pub balance: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ReleaseCollateralEvent<T: Collateral> {
    pub account_id: T::AccountId,
    pub balance: T::DOT,
}
