use crate::pallet_security::{Security, SecurityEventsDecoder};
use core::marker::PhantomData;
pub use module_vault_registry::Vault;
use parity_scale_codec::{Codec, Encode, EncodeLike};
use sp_runtime::traits::Member;
use std::fmt::Debug;
use substrate_subxt::balances::{Balances, BalancesEventsDecoder};
use substrate_subxt::system::{System, SystemEventsDecoder};
use substrate_subxt_proc_macro::{module, Store};

#[module]
pub trait VaultRegistry: System + Security + Balances {
    type PolkaBTC: Codec + EncodeLike + Member + Default;
}

#[derive(Clone, Debug, Eq, PartialEq, Store, Encode)]
pub struct VaultsStore<T: VaultRegistry> {
    #[store(returns = Vault<T::AccountId, T::BlockNumber, T::PolkaBTC>)]
    pub _runtime: PhantomData<T>,
    pub account_id: T::AccountId,
}
