use super::{Core, CoreEventsDecoder};
use core::marker::PhantomData;
pub use module_vault_registry::{Vault, VaultStatus};
use parity_scale_codec::{Decode, Encode};
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait VaultRegistry: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RegisterVaultCall<T: VaultRegistry> {
    pub collateral: T::DOT,
    pub btc_address: T::H160,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RegisterVaultEvent<T: VaultRegistry> {
    pub account_id: T::AccountId,
    pub collateral: T::DOT,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct LockAdditionalCollateralCall<T: VaultRegistry> {
    pub amount: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct LockAdditionalCollateralEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub new_collateral: T::DOT,
    pub total_collateral: T::DOT,
    pub free_collateral: T::DOT,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct WithdrawCollateralCall<T: VaultRegistry> {
    pub amount: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct WithdrawCollateralEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub withdrawn_collateral: T::DOT,
    pub total_collateral: T::DOT,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct VaultsStore<T: VaultRegistry> {
    #[store(returns = Vault<T::AccountId, T::BlockNumber, T::PolkaBTC>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct LiquidationCollateralThresholdStore<T: VaultRegistry> {
    #[store(returns = T::u128)]
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct IncreaseToBeIssuedTokensEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub tokens: T::BTCBalance,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct UpdateBtcAddressCall<T: VaultRegistry> {
    pub btc_address: T::H160,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct UpdateBtcAddressEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub btc_address: T::H160,
}
