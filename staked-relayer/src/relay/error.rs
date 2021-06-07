use bitcoin::Error as BitcoinError;
use runtime::Error as InterBtcError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to decode hash")]
    DecodeHash,
    #[error("Failed to serialize block header")]
    SerializeHeader,

    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("InterBtcError: {0}")]
    InterBtcError(#[from] InterBtcError),
}
