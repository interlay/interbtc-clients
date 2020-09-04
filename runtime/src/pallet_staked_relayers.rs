use crate::pallet_security::{Security, SecurityEventsDecoder};
use core::marker::PhantomData;
use module_bitcoin::types::H256Le;
use module_security::ErrorCode;
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
    type U256: Codec + EncodeLike + Member + Default;
    type StatusCode: Codec + EncodeLike + Member + Default;
    type ErrorCode: Codec + EncodeLike + Member + Default;
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
    pub add_error: Option<ErrorCode>,
    pub remove_error: Option<ErrorCode>,
    pub block_hash: Option<H256Le>,
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
    pub status_update_id: T::U256,
    pub status_code: T::StatusCode,
    pub add_error: T::ErrorCode,
    pub remove_error: T::ErrorCode,
    pub account_id: T::AccountId,
}

// #[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
// pub struct ActiveStakedRelayersStore<T: StakedRelayers> {
//     #[store(returns = u64)]
//     pub _runtime: PhantomData<T>,
//     pub account_id: T::AccountId,
// }

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ActiveStakedRelayersCountStore<T: StakedRelayers> {
    #[store(returns = u64)]
    pub _runtime: PhantomData<T>,
}
