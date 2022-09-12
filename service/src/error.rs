use bitcoin::Error as BitcoinError;
use hyper::{http::Error as HyperHttpError, Error as HyperError};
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, num::ParseIntError};
use thiserror::Error;
use tokio::task::JoinError as TokioJoinError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Received an invalid response")]
    InvalidResponse,
    #[error("Client has shutdown")]
    ClientShutdown,
    #[error("OsString parsing error")]
    OsStringError,
    #[error("There is a service already running on the system, with pid {0}")]
    ServiceAlreadyRunning(u32),
    #[error("Process with pid {0} not found")]
    ProcessNotFound(String),

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("HyperError: {0}")]
    HyperError(#[from] HyperError),
    #[error("HyperHttpError: {0}")]
    HyperHttpError(#[from] HyperHttpError),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("TokioError: {0}")]
    TokioError(#[from] TokioJoinError),
    #[error("System I/O error: {0}")]
    IoError(#[from] IoError),

    /// Other error
    #[error("Other: {0}")]
    Other(String),
}
