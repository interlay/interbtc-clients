use bitcoin::{ConversionError, Error as BitcoinError};
use hex::FromHexError;
use runtime::Error as RuntimeError;
use std::array::TryFromSliceError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid request id")]
    InvalidRequestId,
    #[error("Unknown Bitcoin network")]
    UnknownBitcoinNetwork,

    #[error("Http error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("AddressConversionError: {0}")]
    AddressConversionError(#[from] ConversionError),
    #[error("FromHexError: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("TryFromSliceError: {0}")]
    TryFromSliceError(#[from] TryFromSliceError),
}
