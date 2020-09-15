use core::marker::PhantomData;
use frame_support::Parameter;
use parity_scale_codec::{Codec, Encode};
use sp_runtime::traits::{AtLeast32Bit, MaybeSerialize, Member};
use std::fmt::Debug;
use substrate_subxt::balances::AccountData;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait DOT: System {
    type Balance: Parameter
        + Member
        + AtLeast32Bit
        + Codec
        + Default
        + Copy
        + MaybeSerialize
        + Debug
        + From<<Self as System>::BlockNumber>;
}

/// The balance of an account.
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct AccountStore<T: DOT> {
    #[store(returns = AccountData<T::Balance>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
}
