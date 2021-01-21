use bitcoin::BitcoinError;
use runtime::Error as PolkaBtcError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to decode hash")]
    DecodeHash,
    #[error("Failed to serialize block header")]
    SerializeHeader,

    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("PolkaBtcError: {0}")]
    PolkaBtcError(#[from] PolkaBtcError),
}
