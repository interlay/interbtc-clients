use super::{Core, CoreEventsDecoder};
use parity_scale_codec::Encode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Store};
use core::marker::PhantomData;

#[module]
pub trait Fee: Core {}

/// Current BTC/DOT exchange rate
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct IssueGriefingCollateralStore<T: Fee> {
    #[store(returns = T::UnsignedFixedPoint)]
    pub _runtime: PhantomData<T>,
}