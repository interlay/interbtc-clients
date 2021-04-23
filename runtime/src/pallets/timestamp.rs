use codec::{Codec, Encode, EncodeLike};
use core::marker::PhantomData;
use sp_runtime::traits::{AtLeast32Bit, Member};
use substrate_subxt::system::System;
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait Timestamp: System {
    /// Type used for expressing timestamp.
    type Moment: Codec + AtLeast32Bit + EncodeLike + Member + Default;
}

/// Current time for the current block.
#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct NowStore<T: Timestamp> {
    #[store(returns = T::Moment)]
    pub _runtime: PhantomData<T>,
}
