#![allow(clippy::enum_variant_names)]

use codec::Error as CodecError;
use jsonrpsee::core::Error as JsonRpcCoreError;
use std::io::Error as OsError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("JsonRpcCoreError: {0}")]
    JsonRpcCoreError(#[from] JsonRpcCoreError),
    #[error("System command error: {0}")]
    OsError(#[from] OsError),
    // #[error("JsonRpcHttpError: {0}")]
    // JsonRpcHttpError(#[from] JsonRpcHttpError),
    #[error("Failed to derive the release name of the vault")]
    ClientNameDerivationError,
}
