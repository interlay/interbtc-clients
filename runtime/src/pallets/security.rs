use core::marker::PhantomData;
pub use module_security::{ErrorCode, StatusCode};
use parity_scale_codec::Encode;
use parity_scale_codec::{Codec, EncodeLike};
use sp_core::U256;
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait Security: System {
    type ErrorCodes: Codec + EncodeLike + Member + Default;
}

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
