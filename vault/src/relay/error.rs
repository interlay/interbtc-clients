#![allow(clippy::enum_variant_names)]

use bitcoin::Error as BitcoinError;
use runtime::Error as RuntimeError;
use thiserror::Error;

#[cfg(test)]
use std::mem::discriminant;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Client already initialized")]
    AlreadyInitialized,
    #[error("Client has not been initialized")]
    NotInitialized,
    #[error("Block already submitted")]
    BlockExists,
    #[error("Cannot read the best height")]
    CannotFetchBestHeight,
    #[error("Block hash not found for the given height")]
    BlockHashNotFound,
    #[error("Failed to decode hash")]
    DecodeHash,
    #[error("Failed to serialize block header")]
    SerializeHeader,

    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
}

#[cfg(test)]
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}
