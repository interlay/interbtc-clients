use codec::{Codec, Decode, Encode, EncodeLike};
use core::marker::PhantomData;
use frame_support::Parameter;
use sp_runtime::traits::{AtLeast32Bit, MaybeSerialize, Member};
use std::fmt::Debug;
use substrate_subxt::{balances::AccountData, system::System};
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Tokens: System {
    type Balance: Parameter
        + Member
        + AtLeast32Bit
        + Codec
        + Default
        + Copy
        + MaybeSerialize
        + Debug
        + From<<Self as System>::BlockNumber>;
    type CurrencyId: Codec + EncodeLike + Send + Sync;
}

/// The balance of an account.
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct AccountStore<T: Tokens> {
    #[store(returns = AccountData<T::Balance>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
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
