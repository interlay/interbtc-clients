use super::{Core, CoreEventsDecoder};
use parity_scale_codec::Decode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event};

#[module]
pub trait Treasury: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct MintEvent<T: Treasury> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct LockEvent<T: Treasury> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct BurnEvent<T: Treasury> {
    pub account_id: T::AccountId,
    pub amount: T::Balance,
}
