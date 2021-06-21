use bitcoin::Error as BitcoinError;
use runtime::Error as InterBtcError;
use std::mem::discriminant;
use thiserror::Error;

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
    #[error("InterBtcError: {0}")]
    InterBtcError(#[from] InterBtcError),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}
