use super::{Core, CoreEventsDecoder};
use btc_parachain_runtime::{Event, Hash};
use core::marker::PhantomData;
pub use module_bitcoin::types::H256Le;
use parity_scale_codec::Encode;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait System: Core {}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct EventsStore<T: System> {
    #[store(returns = Vec<frame_system::EventRecord<Event, Hash>>)]
    pub _runtime: PhantomData<T>,
}
