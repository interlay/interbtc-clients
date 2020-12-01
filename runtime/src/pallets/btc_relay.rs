use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
pub use module_bitcoin::{formatter::Formattable, types::*};
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

pub type BitcoinBlockHeight = u32;

#[module]
pub trait BTCRelay: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct InitializeCall<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub raw_block_header: RawBlockHeader,
    pub block_height: BitcoinBlockHeight,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct StoreBlockHeaderCall<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub raw_block_header: RawBlockHeader,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct StoreBlockHeadersCall<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub raw_block_headers: Vec<RawBlockHeader>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct BestBlockStore<T: BTCRelay> {
    #[store(returns = T::H256Le)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct BestBlockHeightStore<T: BTCRelay> {
    #[store(returns = BitcoinBlockHeight)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ChainsHashesStore<T: BTCRelay> {
    #[store(returns = T::H256Le)]
    pub _runtime: PhantomData<T>,
    pub chain_index: u32,
    pub block_height: BitcoinBlockHeight,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct BlockHeadersStore<T: BTCRelay> {
    #[store(returns = T::RichBlockHeader)]
    pub block_hash: T::H256Le,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct InitializedEvent<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub block_height: BitcoinBlockHeight,
    pub block_header_hash: T::H256Le,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct StoreMainChainHeaderEvent<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub block_height: BitcoinBlockHeight,
    pub block_header_hash: T::H256Le,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct StableBitcoinConfirmationsStore<T: BTCRelay> {
    #[store(returns = u32)]
    pub _runtime: PhantomData<T>,
}
