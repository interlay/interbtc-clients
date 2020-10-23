use super::{Core, CoreEventsDecoder};
pub use module_bitcoin::types::H256Le;
use parity_scale_codec::{Decode, Encode};
pub use sp_core::{H160, H256};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event};

#[module]
pub trait Replace: Core { }

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
}
#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AuctionReplaceCall<T: Replace> {
    pub old_vault: T::AccountId,
    pub btc_amount: T::PolkaBTC,
    pub collateral: T::DOT,
}
#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteReplaceCall<T: Replace> {
    pub replace_id: T::H256,
    pub tx_id: T::H256Le,
    pub _tx_block_height: u32,
    pub merkle_proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelReplaceCall<T: Replace> {
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestReplaceEvent<T: Replace> {
    pub vault_id: T::AccountId,
    pub amount: T::PolkaBTC,
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct WithdrawReplaceEvent<T: Replace> {
    pub vault_id: T::AccountId,
    pub request_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct AcceptReplaceEvent<T: Replace> {
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
    pub replace_id: T::H256,
    pub collateral: T::DOT,
    pub btc_amount: T::PolkaBTC,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteReplaceEvent<T: Replace> {
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct AuctionReplaceEvent<T: Replace> {
    pub old_vault_id: T::AccountId,
    pub new_vault_id: T::AccountId,
    pub replace_id: T::H256,
    pub btc_amount: T::PolkaBTC,
    pub collateral: T::DOT,
    pub current_height: T::BlockNumber,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelReplaceEvent<T: Replace> {
    pub new_vault_id: T::AccountId,
    pub old_vault_id: T::AccountId,
    pub replace_id: T::H256,
}
