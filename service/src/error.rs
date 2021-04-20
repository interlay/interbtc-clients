use hyper::{http::Error as HyperHttpError, Error as HyperError};
use serde_json::Error as SerdeJsonError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Received an invalid response")]
    InvalidResponse,

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("HyperError: {0}")]
    HyperError(#[from] HyperError),
    #[error("HyperHttpError: {0}")]
    HyperHttpError(#[from] HyperHttpError),
}
