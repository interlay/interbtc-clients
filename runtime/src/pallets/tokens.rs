use super::Core;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use std::fmt::Debug;
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

// https://github.com/open-web3-stack/open-runtime-module-library/blob/bb6ad7a629ac53ed138d30583d36971b3030322d/tokens/src/lib.rs#L117
#[derive(Encode, Decode, Clone, PartialEq, Eq, Default)]
pub struct AccountData<Balance> {
    pub free: Balance,
    pub reserved: Balance,
    pub frozen: Balance,
}

#[module]
pub trait Tokens: Core {}

/// The balance of an account.
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct AccountsStore<T: Tokens> {
    #[store(returns = AccountData<T::Balance>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
    pub currency_id: T::CurrencyId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct EndowedEvent<T: Tokens> {
    pub currency_id: T::CurrencyId,
    pub account_id: T::AccountId,
    pub balance: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ReservedEvent<T: Tokens> {
    pub currency_id: T::CurrencyId,
    pub account_id: T::AccountId,
    pub balance: T::Balance,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct TransferCall<'a, T: Tokens> {
    pub dest: &'a <T as System>::Address,
    pub currency_id: T::CurrencyId,
    #[codec(compact)]
    pub amount: T::Balance,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct TransferEvent<T: Tokens> {
    pub currency_id: T::CurrencyId,
    pub from: <T as System>::AccountId,
    pub to: <T as System>::AccountId,
    pub amount: T::Balance,
}
