use super::Core;
use crate::ReplaceRequest;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use primitives::{VaultCurrencyPair, VaultId};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait Replace: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RequestReplaceCall<T: Replace> {
    currency_pair: VaultCurrencyPair<T::CurrencyId>,
    #[codec(compact)]
    pub btc_amount: T::Wrapped,
    #[codec(compact)]
    pub griefing_collateral: T::Collateral,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct WithdrawReplaceCall<T: Replace> {
    currency_pair: VaultCurrencyPair<T::CurrencyId>,
    #[codec(compact)]
    pub amount: T::Wrapped,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct AcceptReplaceCall<'a, T: Replace> {
    currency_pair: VaultCurrencyPair<T::CurrencyId>,
    pub old_vault: &'a VaultId<T::AccountId, T::CurrencyId>,
    #[codec(compact)]
    pub amount_btc: T::Wrapped,
    #[codec(compact)]
    pub collateral: T::Collateral,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct ExecuteReplaceCall<'a, T: Replace> {
    pub replace_id: T::H256,
    pub merkle_proof: &'a [u8],
    pub raw_tx: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct CancelReplaceCall<T: Replace> {
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RequestReplaceEvent<T: Replace> {
    pub old_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub amount_btc: T::Wrapped,
    pub griefing_collateral: T::Collateral,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct WithdrawReplaceEvent<T: Replace> {
    pub old_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub withdrawn_tokens: T::Wrapped,
    pub withdrawn_griefing_collateral: T::Collateral,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct AcceptReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub new_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub amount_btc: T::Wrapped,
    pub collateral: T::Collateral,
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct ExecuteReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub old_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub new_vault_id: VaultId<T::AccountId, T::CurrencyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct CancelReplaceEvent<T: Replace> {
    pub replace_id: T::H256,
    pub new_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub old_vault_id: VaultId<T::AccountId, T::CurrencyId>,
    pub griefing_collateral: T::Collateral,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ReplacePeriodStore<T: Replace> {
    #[store(returns = T::BlockNumber)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ReplaceBtcDustValueStore<T: Replace> {
    #[store(returns = T::Wrapped)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct ReplaceRequestsStore<T: Replace> {
    #[store(returns = ReplaceRequest<T::AccountId, T::BlockNumber, T::Balance, T::CurrencyId>)]
    pub _runtime: PhantomData<T>,
    pub replace_id: T::H256,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct SetReplacePeriodCall<T: Replace> {
    pub period: T::BlockNumber,
    pub _runtime: PhantomData<T>,
}
