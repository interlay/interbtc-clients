use bitcoin::Error as BitcoinError;
use runtime::{substrate_subxt::Error as XtError, Error as RuntimeError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
}
