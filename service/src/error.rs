use bitcoin::Error as BitcoinError;
use hyper::{http::Error as HyperHttpError, Error as HyperError};
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeJsonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Received an invalid response")]
    InvalidResponse,
    #[error("Client has shutdown")]
    ClientShutdown,

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("HyperError: {0}")]
    HyperError(#[from] HyperError),
    #[error("HyperHttpError: {0}")]
    HyperHttpError(#[from] HyperHttpError),

    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),

    /// Other error
    #[error("Other: {0}")]
    Other(String),
}
