use crate::runtime::pallet_security::Security;
use crate::runtime::pallet_security::SecurityEventsDecoder;
use core::marker::PhantomData;
use module_bitcoin::types::{H256Le, RawBlockHeader};
use parity_scale_codec::{Codec, Decode, Encode, EncodeLike};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Call, Event, Store};

pub type BitcoinBlockHeight = u32;

#[module]
pub trait BTCRelay: System + Security {
    type H256Le: Codec + EncodeLike + Member + Default;
}

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

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct BestBlockHeightStore<T: BTCRelay> {
    #[store(returns = BitcoinBlockHeight)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct InitializedEvent<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub block_height: BitcoinBlockHeight,
    pub block_header_hash: H256Le,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct StoreMainChainHeaderEvent<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub block_height: BitcoinBlockHeight,
    pub block_header_hash: H256Le,
}
