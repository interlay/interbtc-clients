#![allow(clippy::enum_variant_names)]

use chrono::ParseError as ChronoParseError;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use kv::Error as KvError;
use parity_scale_codec::Error as CodecError;
use reqwest::Error as ReqwestError;
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, net::AddrParseError};
use thiserror::Error;
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] JsonRpcError),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("Kv store error: {0}")]
    KvError(#[from] KvError),
    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("UrlParseError: {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("Error parsing datetime string: {0}")]
    DatetimeParsingError(#[from] ChronoParseError),
    #[error("IoError: {0}")]
    IoError(#[from] IoError),
    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),

    #[error("Requester balance already sufficient")]
    AccountBalanceExceedsMaximum,
    #[error("Requester was recently funded")]
    AccountAlreadyFunded,
    #[error("Mathematical operation error")]
    MathError,
    #[error("Terms and conditions not signed")]
    SignatureMissing,
}
