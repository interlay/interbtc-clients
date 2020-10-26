use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
pub use module_vault_registry::Vault;
use parity_scale_codec::{Decode, Encode};
use sp_core::H160;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait VaultRegistry: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RegisterVaultCall<T: VaultRegistry> {
    pub collateral: T::DOT,
    pub btc_address: H160,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RegisterVaultEvent<T: VaultRegistry> {
    pub account_id: T::AccountId,
    pub collateral: T::DOT,
}

// TODO: liquidate event

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct VaultsStore<T: VaultRegistry> {
    #[store(returns = Vault<T::AccountId, T::BlockNumber, T::PolkaBTC>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct LiquidationCollateralThresholdStore<T: VaultRegistry> {
    #[store(returns = u128)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct IncreaseToBeIssuedTokensEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub tokens: T::BTCBalance,
}
