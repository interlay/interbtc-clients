use bitcoin::{ConversionError, Error as BitcoinError};
use runtime::Error as RuntimeError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("AddressConversionError: {0}")]
    AddressConversionError(#[from] ConversionError),
}
