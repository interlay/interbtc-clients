use super::Core;
use core::marker::PhantomData;
pub use module_security::{ErrorCode, StatusCode};
use parity_scale_codec::{Decode, Encode};
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
    #[store(returns = StatusCode)]
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
