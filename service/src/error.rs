use bitcoin::Error as BitcoinError;
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, num::ParseIntError};
use thiserror::Error;
use tokio::task::JoinError as TokioJoinError;

#[derive(Error, Debug)]
pub enum Error<InnerError> {
    #[error("Abort: {0}")]
    Abort(InnerError),
    #[error("Retry: {0}")]
    Retry(InnerError),

    #[error("Client has shutdown")]
    ClientShutdown,
    #[error("OsString parsing error")]
    OsStringError,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("There is a service already running on the system, with pid {0}")]
    ServiceAlreadyRunning(u32),
    #[error("Process with pid {0} not found")]
    ProcessNotFound(String),

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
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
}
