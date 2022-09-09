use crate::{
    consensus::encode::Error as BitcoinEncodeError, hashes::hex::Error as HexError, secp256k1::Error as Secp256k1Error,
    util::address::Error as BitcoinAddressError,
};
use reqwest::Error as ReqwestError;
use serde_json::Error as SerdeJsonError;
use std::{
    num::{ParseIntError, TryFromIntError},
    sync::PoisonError,
};
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No witness to sign")]
    NoWitness,
    #[error("No previous output for input")]
    NoPrevOut,
    #[error("Cannot use invalid prevout")]
    InvalidPrevOut,
    #[error("Cannot construct address")]
    InvalidAddress,
    #[error("Cannot construct public key")]
    InvalidPublicKey,
    #[error("No private key found for address")]
    NoPrivateKey,
    #[error("Not enough inputs to fund transaction")]
    NotEnoughInputs,
    #[error("No change address available")]
    NoChangeAddress,
    #[error("Cannot open key store")]
    CannotOpenKeyStore,

    #[error("Secp256k1Error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),
    #[error("BitcoinAddressError: {0}")]
    BitcoinAddressError(#[from] BitcoinAddressError),
    #[error("BitcoinEncodeError: {0}")]
    BitcoinEncodeError(#[from] BitcoinEncodeError),

    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("ParseError: {0}")]
    ParseError(#[from] ParseError),

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),

    #[error("HexError: {0}")]
    HexError(#[from] HexError),

    #[error("TryFromIntError: {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::CannotOpenKeyStore
    }
}
