use super::Core;
use codec::Encode;
use core::marker::PhantomData;
use std::fmt::Debug;
use substrate_subxt::Encoded;
use substrate_subxt_proc_macro::{module, Call};

#[module]
pub trait Utility: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Call, Encode)]
pub struct BatchCall<T: Utility> {
    pub _runtime: PhantomData<T>,
    pub calls: Vec<Encoded>,
}
