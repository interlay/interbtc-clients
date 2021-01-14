use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
use parity_scale_codec::Encode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait Fee: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssueGriefingCollateralStore<T: Fee> {
    #[store(returns = T::UnsignedFixedPoint)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssueFeeStore<T: Fee> {
    #[store(returns = T::UnsignedFixedPoint)]
    pub _runtime: PhantomData<T>,
}

pub struct ReplaceGriefingCollateralStore<T: Fee> {
    #[store(returns = T::UnsignedFixedPoint)]
    pub _runtime: PhantomData<T>,
}
