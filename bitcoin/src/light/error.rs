use crate::{
    psbt::Error as PsbtError, secp256k1::Error as Secp256k1Error, util::address::Error as AddressError, ElectrsError,
};
use bitcoincore_rpc::bitcoin::util::sighash::Error as SighashError;
use std::sync::PoisonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No previous output for input")]
    NoPrevOut,
    #[error("Cannot use invalid prevout")]
    InvalidPrevOut,
    #[error("Cannot construct address")]
    InvalidAddress,
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
    #[error("AddressError: {0}")]
    AddressError(#[from] AddressError),
    #[error("PsbtError: {0}")]
    PsbtError(#[from] PsbtError),

    #[error("ElectrsError: {0}")]
    ElectrsError(#[from] ElectrsError),

    #[error("SighashError: {0}")]
    SighashError(#[from] SighashError),
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Self::CannotOpenKeyStore
    }
}
