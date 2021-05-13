use super::Core;
use crate::BitcoinBlockHeight;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Event, Store};

#[module]
pub trait BTCRelay: Core {}

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
    pub account_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct StoreMainChainHeaderEvent<T: BTCRelay> {
    pub _runtime: PhantomData<T>,
    pub block_height: BitcoinBlockHeight,
    pub block_header_hash: T::H256Le,
    pub account_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct StableBitcoinConfirmationsStore<T: BTCRelay> {
    #[store(returns = u32)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct StableParachainConfirmationsStore<T: BTCRelay> {
    #[store(returns = T::BlockNumber)]
    pub _runtime: PhantomData<T>,
}
