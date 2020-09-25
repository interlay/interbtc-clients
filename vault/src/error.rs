use crate::bitcoin::BitcoinError;
use runtime::Error as RuntimeError;
use std::env::VarError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Read env error: {0}: {1}")]
    ReadVar(String, VarError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
}
