use crate::security::{Security, SecurityEventsDecoder};
use core::marker::PhantomData;
pub use module_staked_relayers::types::StatusUpdate;
pub use module_staked_relayers::Error as StakedRelayersError;
use parity_scale_codec::{Codec, Decode, Encode, EncodeLike};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait StakedRelayers: System + Security + Balances {
    type DOT: Codec + EncodeLike + Member + Default;
    type H256Le: Codec + EncodeLike + Member + Default;
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RegisterStakedRelayerCall<T: StakedRelayers> {
    pub stake: T::DOT,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct DeregisterStakedRelayerCall<T: StakedRelayers> {
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SuggestStatusUpdateCall<T: StakedRelayers> {
    pub deposit: T::DOT,
    pub status_code: T::StatusCode,
    pub add_error: Option<T::ErrorCode>,
    pub remove_error: Option<T::ErrorCode>,
    pub block_hash: Option<T::H256Le>,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct VoteOnStatusUpdateCall<T: StakedRelayers> {
    pub _runtime: PhantomData<T>,
    pub status_update_id: u64,
    pub approve: bool,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ReportOracleOffline<T: StakedRelayers> {
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ReportVaultTheftCall<T: StakedRelayers> {
    pub vault_id: T::AccountId,
    pub tx_id: T::H256Le,
    pub tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RegisterStakedRelayerEvent<T: StakedRelayers> {
    pub account_id: T::AccountId,
    pub maturity: T::BlockNumber,
    pub collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct DeregisterStakedRelayerEvent<T: StakedRelayers> {
    pub account_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct StatusUpdateSuggestedEvent<T: StakedRelayers> {
    pub status_update_id: u64,
    pub account_id: T::AccountId,
    pub status_code: T::StatusCode,
    pub add_error: Option<T::ErrorCode>,
    pub remove_error: Option<T::ErrorCode>,
    pub block_hash: Option<T::H256Le>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteStatusUpdateEvent<T: StakedRelayers> {
    pub status_code: T::StatusCode,
    pub add_error: Option<T::ErrorCode>,
    pub remove_error: Option<T::ErrorCode>,
    pub block_hash: Option<T::H256Le>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ActiveStakedRelayersStore<'a, T: StakedRelayers> {
    #[store(returns = u64)]
    pub _runtime: PhantomData<T>,
    pub account_id: &'a T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ActiveStakedRelayersCountStore<T: StakedRelayers> {
    #[store(returns = u64)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ActiveStatusUpdatesStore<T: StakedRelayers> {
    #[store(returns = StatusUpdate<T::AccountId, T::BlockNumber, T::DOT>)]
    pub _runtime: PhantomData<T>,
    pub status_id: u64,
}
