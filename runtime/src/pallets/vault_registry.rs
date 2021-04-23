use super::Core;
use crate::Vault;
use codec::{Decode, Encode};
use core::marker::PhantomData;
use std::fmt::Debug;
use substrate_subxt_proc_macro::{module, Call, Event, Store};

#[module]
pub trait VaultRegistry: Core {}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RegisterVaultCall<T: VaultRegistry> {
    #[codec(compact)]
    pub collateral: T::DOT,
    pub public_key: T::BtcPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RegisterVaultEvent<T: VaultRegistry> {
    pub account_id: T::AccountId,
    pub collateral: T::DOT,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct LockAdditionalCollateralCall<T: VaultRegistry> {
    #[codec(compact)]
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
    #[codec(compact)]
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
    #[store(returns = Vault<T::AccountId, T::BlockNumber, T::PolkaBTC, T::DOT>)]
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

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct UpdatePublicKeyCall<T: VaultRegistry> {
    pub public_key: T::BtcPublicKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct UpdatePublicKeyEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub public_key: T::BtcPublicKey,
}

#[derive(Clone, Debug, PartialEq, Call, Encode)]
pub struct RegisterAddressCall<T: VaultRegistry> {
    pub btc_address: T::BtcAddress,
}

#[derive(Clone, Debug, Eq, PartialEq, Event, Decode)]
pub struct RegisterAddressEvent<T: VaultRegistry> {
    pub vault_id: T::AccountId,
    pub btc_address: T::BtcAddress,
}
