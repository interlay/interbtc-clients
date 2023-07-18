use crate::SS58_PREFIX;
use base58::{FromBase58, ToBase58};
use blake2::{Blake2b512, Digest};
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
/// A 32-byte cryptographic identifier. This is a simplified version of Substrate's
/// `sp_core::crypto::AccountId32`. To obtain more functionality, convert this into
/// that type.
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
    Default,
)]
pub struct AccountId32(pub [u8; 32]);

impl AsRef<[u8]> for AccountId32 {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsRef<[u8; 32]> for AccountId32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for AccountId32 {
    fn from(x: [u8; 32]) -> Self {
        AccountId32(x)
    }
}

impl AccountId32 {
    pub fn new(value: [u8; 32]) -> Self {
        AccountId32(value)
    }

    // Return the ss58-check string for this key. Adapted from `sp_core::crypto`. We need this to
    // serialize our account appropriately but otherwise don't care.
    pub fn to_ss58check(&self) -> String {
        // For serializing to a string to obtain the account nonce, we use the default substrate
        // prefix (since we have no way to otherwise pick one). It doesn't really matter, since when
        // it's deserialized back in system_accountNextIndex, we ignore this (so long as it's valid).
        // prefix <= 63 just take up one byte at the start:
        let mut v = vec![SS58_PREFIX as u8];
        // then push the account ID bytes.
        v.extend(self.0);
        // then push a 2 byte checksum of what we have so far.
        let r = ss58hash(&v);
        v.extend(&r[0..2]);
        // then encode to base58.
        v.to_base58()
    }

    // This isn't strictly needed, but to give our AccountId32 a little more usefulness, we also
    // implement the logic needed to decode an AccountId32 from an SS58 encoded string. This is exposed
    // via a `FromStr` impl.
    fn from_ss58check(s: &str) -> Result<Self, FromSs58Error> {
        const CHECKSUM_LEN: usize = 2;
        let body_len = 32;

        let data = s.from_base58().map_err(|_| FromSs58Error::BadBase58)?;
        if data.len() < 2 {
            return Err(FromSs58Error::BadLength);
        }
        let prefix_len = match data[0] {
            0..=63 => 1,
            64..=127 => 2,
            _ => return Err(FromSs58Error::InvalidPrefix),
        };
        if data.len() != prefix_len + body_len + CHECKSUM_LEN {
            return Err(FromSs58Error::BadLength);
        }
        let hash = ss58hash(&data[0..body_len + prefix_len]);
        let checksum = &hash[0..CHECKSUM_LEN];
        if data[body_len + prefix_len..body_len + prefix_len + CHECKSUM_LEN] != *checksum {
            // Invalid checksum.
            return Err(FromSs58Error::InvalidChecksum);
        }
        let result = data[prefix_len..body_len + prefix_len]
            .try_into()
            .map_err(|_| FromSs58Error::BadLength)?;
        Ok(AccountId32(result))
    }
}

/// An error obtained from trying to interpret an SS58 encoded string into an AccountId32
#[derive(thiserror::Error, Clone, Copy, Eq, PartialEq, Debug)]
#[allow(missing_docs)]
pub enum FromSs58Error {
    #[error("Base 58 requirement is violated")]
    BadBase58,
    #[error("Length is bad")]
    BadLength,
    #[error("Invalid checksum")]
    InvalidChecksum,
    #[error("Invalid SS58 prefix byte.")]
    InvalidPrefix,
}

// We do this just to get a checksum to help verify the validity of the address in to_ss58check
fn ss58hash(data: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"SS58PRE";
    let mut ctx = Blake2b512::new();
    ctx.update(PREFIX);
    ctx.update(data);
    ctx.finalize().to_vec()
}

impl Serialize for AccountId32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_ss58check())
    }
}

impl<'de> Deserialize<'de> for AccountId32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        AccountId32::from_ss58check(&String::deserialize(deserializer)?)
            .map_err(|e| serde::de::Error::custom(format!("{e:?}")))
    }
}

impl std::fmt::Display for AccountId32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_ss58check())
    }
}

impl std::str::FromStr for AccountId32 {
    type Err = FromSs58Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AccountId32::from_ss58check(s)
    }
}

impl From<sp_runtime::AccountId32> for AccountId32 {
    fn from(value: sp_runtime::AccountId32) -> Self {
        Self(value.into())
    }
}
impl From<sp_core::sr25519::Public> for AccountId32 {
    fn from(value: sp_core::sr25519::Public) -> Self {
        let acc: sp_runtime::AccountId32 = value.into();
        acc.into()
    }
}
impl From<sp_core::ed25519::Public> for AccountId32 {
    fn from(value: sp_core::ed25519::Public) -> Self {
        let acc: sp_runtime::AccountId32 = value.into();
        acc.into()
    }
}

impl From<sp_keyring::Sr25519Keyring> for AccountId32 {
    fn from(account: sp_keyring::Sr25519Keyring) -> Self {
        let account = account.to_account_id();
        AccountId32(account.into())
    }
}
