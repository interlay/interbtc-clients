use crate::BitcoinError;
use std::env::VarError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Read env error: {0}: {1}")]
    ReadVar(String, VarError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
}
