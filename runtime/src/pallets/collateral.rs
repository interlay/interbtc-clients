use crate::security::Security;
use crate::security::SecurityEventsDecoder;
use parity_scale_codec::{Codec, Decode, EncodeLike};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Event};

#[module]
pub trait Collateral: System + Security {
    type DOT: Codec + EncodeLike + Member + Default;
    type Balance: Codec + EncodeLike + Member + Default;
}

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
