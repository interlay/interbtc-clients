#![allow(clippy::too_many_arguments)]

use super::Core;
use crate::{BitcoinBlockHeight, RawBlockHeader};
use codec::{Decode, Encode};
use core::marker::PhantomData;
use std::fmt::Debug;
use substrate_subxt::balances::Balances;
use substrate_subxt_proc_macro::{module, Call, Event};

#[module]
pub trait StakedRelayers: Core + Balances {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ReportVaultTheftCall<T: StakedRelayers> {
    pub vault_id: T::AccountId,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct VaultTheftEvent<T: StakedRelayers> {
    pub vault_id: T::AccountId,
    pub txid: T::H256Le,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct InitializeCall<T: StakedRelayers> {
    pub _runtime: PhantomData<T>,
    pub raw_block_header: RawBlockHeader,
    pub block_height: BitcoinBlockHeight,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct StoreBlockHeaderCall<T: StakedRelayers> {
    pub _runtime: PhantomData<T>,
    pub raw_block_header: RawBlockHeader,
}
