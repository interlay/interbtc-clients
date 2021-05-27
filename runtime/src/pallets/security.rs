use super::Core;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use sp_core::U256;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event, Store};

#[module]
pub trait Security: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct NonceStore<T: Security> {
    #[store(returns = U256)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ParachainStatusStore<T: Security> {
    #[store(returns = T::StatusCode)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ErrorsStore<T: Security> {
    #[store(returns = T::ErrorCodes)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RecoverFromErrorsEvent<T: Security> {
    pub status_code: T::StatusCode,
    pub error_codes: Vec<T::ErrorCode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ActiveBlockCountStore<T: Security> {
    #[store(returns = T::BlockNumber)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct UpdateActiveBlockEvent<T: Security> {
    pub height: T::BlockNumber,
}
