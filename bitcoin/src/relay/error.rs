#![allow(clippy::enum_variant_names)]

use crate::Error as BitcoinError;
use thiserror::Error;

#[cfg(test)]
use std::mem::discriminant;

#[derive(Error, Debug)]
pub enum Error<RuntimeError> {
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
    #[error("Block header not found for the given height")]
    BlockHeaderNotFound,
    #[error("Failed to decode hash")]
    DecodeHash,
    #[error("Failed to serialize block header")]
    SerializeHeader,

    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    // note: we can't have two #[from]s when one is generic. We'll use map_err for the runtime error
    #[error("RuntimeError: {0}")]
    RuntimeError(RuntimeError),
}
