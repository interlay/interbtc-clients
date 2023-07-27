//! The `AccountId32` type is a wrapper around `sp_core::crypto::AccountId32` with added functionality
//! and convenience methods. It is designed for working with account IDs in the context of
//! Substrate-based blockchains. This wrapper is necessary because the `scale_encode::EncodeAsType` and
//! `scale_decode::DecodeAsType` traits are not implemented for `sp_core::crypto::AccountId32`,
//! but they are required for the latest version of the `subxt` crate.
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32 as Sp_AccountId32, Ss58Codec};
use std::convert::TryInto;
use subxt::utils::Static;

#[derive(
    Hash,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    Debug,
    scale_encode::EncodeAsType,
    scale_decode::DecodeAsType,
)]
pub struct AccountId32(pub Static<Sp_AccountId32>);

impl AccountId32 {
    pub fn new(value: [u8; 32]) -> Self {
        AccountId32(Static(value.into()))
    }

    pub fn to_sp_core_account_id(&self) -> Sp_AccountId32 {
        let account_id = self.0.clone();
        (*account_id).clone().into()
    }
}

impl std::fmt::Display for AccountId32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let wp_accountid = self.clone();
        let sp_accountid = wp_accountid.0;
        let ss58_checks = sp_accountid.to_ss58check();
        write!(f, "{}", ss58_checks)
    }
}

impl std::str::FromStr for AccountId32 {
    type Err = sp_core::crypto::PublicError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let account_id = Sp_AccountId32::from_ss58check(s)?;
        Ok(AccountId32(Static(account_id)))
    }
}

impl Serialize for AccountId32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.clone().0.to_ss58check().as_str())
    }
}

impl<'de> Deserialize<'de> for AccountId32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let account_id = Sp_AccountId32::from_ss58check(&String::deserialize(deserializer)?)
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))?;
        Ok(AccountId32(Static(account_id)))
    }
}

impl From<sp_runtime::AccountId32> for AccountId32 {
    fn from(value: sp_runtime::AccountId32) -> Self {
        AccountId32(Static(value.into()))
    }
}
impl From<sp_core::sr25519::Public> for AccountId32 {
    fn from(value: sp_core::sr25519::Public) -> Self {
        let account_id: Sp_AccountId32 = value.into();
        account_id.into()
    }
}
impl From<sp_core::ed25519::Public> for AccountId32 {
    fn from(value: sp_core::ed25519::Public) -> Self {
        let account_id: Sp_AccountId32 = value.into();
        account_id.into()
    }
}

impl From<sp_keyring::Sr25519Keyring> for AccountId32 {
    fn from(account: sp_keyring::Sr25519Keyring) -> Self {
        let account = account.to_account_id();
        account.into()
    }
}

impl Default for AccountId32 {
    fn default() -> Self {
        AccountId32(Static([0; 32].into()))
    }
}

impl From<[u8; 32]> for AccountId32 {
    fn from(x: [u8; 32]) -> Self {
        AccountId32(Static(x.into()))
    }
}
