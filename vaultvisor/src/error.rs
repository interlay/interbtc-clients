#![allow(clippy::enum_variant_names)]

use codec::Error as CodecError;
use jsonrpsee::core::Error as JsonRpcCoreError;
use reqwest::Error as ReqwestError;
use std::io::Error as OsError;
use thiserror::Error;
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("JsonRpcCoreError: {0}")]
    JsonRpcCoreError(#[from] JsonRpcCoreError),
    #[error("System command error: {0}")]
    OsError(#[from] OsError),
    #[error("HTTP request error: {0}")]
    HttpError(#[from] ReqwestError),
    #[error("UrlParseError: {0}")]
    UrlParseError(#[from] UrlParseError),
    // #[error("JsonRpcHttpError: {0}")]
    // JsonRpcHttpError(#[from] JsonRpcHttpError),
    #[error("Failed to derive the release name of the vault")]
    ClientNameDerivationError,
    #[error("Failed to identify vault binary name in release URI")]
    UnknownBinaryName,
}
