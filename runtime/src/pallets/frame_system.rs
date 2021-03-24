use super::Core;
use core::marker::PhantomData;
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait System: Core {}

pub type RefCount = u32;

/// Information of an account.
#[derive(Clone, Debug, Eq, PartialEq, Default, Decode, Encode)]
pub struct AccountInfo<Index, AccountData> {
    pub nonce: Index,
    pub consumers: RefCount,
    pub providers: RefCount,
    pub data: AccountData,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct AccountStore<T: System> {
    #[store(returns = AccountInfo<T::Index, T::AccountData>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
}
