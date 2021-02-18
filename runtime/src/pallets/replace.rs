use super::Core;
use core::marker::PhantomData;
pub use module_bitcoin::types::H256Le;
pub use module_replace::ReplaceRequest;
use parity_scale_codec::{Decode, Encode};
pub use sp_core::{H160, H256};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Replace: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestReplaceCall<T: Replace> {
    pub btc_amount: T::PolkaBTC,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct WithdrawReplaceCall<T: Replace> {
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AcceptReplaceCall<T: Replace> {
    pub replace_id: T::H256,
    pub collateral: T::DOT,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AuctionReplaceCall<T: Replace> {
    pub old_vault: T::AccountId,
    pub btc_amount: T::PolkaBTC,
    pub collateral: T::DOT,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteReplaceCall<T: Replace> {
    pub replace_id: T::H256,
    pub tx_id: T::H256Le,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelReplaceCall<T: Replace> {
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: T::AccountId,
    pub amount_btc: T::PolkaBTC,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct WithdrawReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct AcceptReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
    pub amount_btc: T::PolkaBTC,
    pub collateral: T::DOT,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct AuctionReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
    pub btc_amount: T::PolkaBTC,
    pub collateral: T::DOT,
    pub reward: T::DOT,
    pub griefing_collateral: T::DOT,
    pub current_height: T::BlockNumber,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub new_vault_id: T::AccountId,
    pub old_vault_id: T::AccountId,
    pub griefing_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ReplacePeriodStore<T: Replace> {
    #[store(returns = u32)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ReplaceRequestsStore<T: Replace> {
    #[store(returns = ReplaceRequest<T::AccountId, T::BlockNumber, T::PolkaBTC, T::DOT>)]
    pub _runtime: PhantomData<T>,
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetReplacePeriodCall<T: Replace> {
    pub period: u32,
    pub _runtime: PhantomData<T>,
}
