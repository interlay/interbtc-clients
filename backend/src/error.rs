use bitcoin::Error as BitcoinError;
use std::num::TryFromIntError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("TryFromIntError: {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
}
