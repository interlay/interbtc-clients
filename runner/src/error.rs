#![allow(clippy::enum_variant_names)]

use backoff::Error as BackoffError;
use codec::Error as CodecError;
use jsonrpsee::core::Error as JsonRpcCoreError;
use nix::Error as OsError;
use reqwest::Error as ReqwestError;
use std::io::Error as IoError;
use thiserror::Error;
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("JsonRpcCoreError: {0}")]
    JsonRpcCoreError(#[from] JsonRpcCoreError),
    #[error("System I/O error: {0}")]
    IoError(#[from] IoError),
    #[error("System command error: {0}")]
    OsError(#[from] OsError),
    #[error("HTTP request error: {0}")]
    HttpError(#[from] ReqwestError),
    #[error("UrlParseError: {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("Failed to derive the release name of the vault")]
    ClientNameDerivationError,
    #[error("Integer conversion error")]
    IntegerConversionError,
    #[error("A client release has not been downloaded")]
    NoDownloadedRelease,
    #[error("No child process has been spawned")]
    NoChildProcess,
    #[error("A child process is already running")]
    ChildProcessExists,
    #[error("Failed to terminate child process")]
    ProcessTerminationFailure,
    #[error("Auto-updater terminated unexpectedly")]
    AutoUpdaterTerminated,
}

impl<E: Into<Error> + Sized> From<BackoffError<E>> for Error {
    fn from(e: BackoffError<E>) -> Self {
        match e {
            BackoffError::Permanent(err) => err.into(),
            BackoffError::Transient(err) => err.into(),
        }
    }
}
