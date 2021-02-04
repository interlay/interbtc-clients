use chrono::ParseError;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use kv::Error as KVError;
use parity_scale_codec::Error as CodecError;
use runtime::Error as RuntimeError;
use std::net::AddrParseError;
use thiserror::Error;

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
    #[error("KV store error: {0}")]
    KVError(#[from] KVError),
    #[error("Error parsing datetime string: {0}")]
    DatetimeParsingError(#[from] ParseError),
    #[error("Too many faucet requests")]
    FaucetOveruseError,
    #[error("Mathematical operation error")]
    MathError,
    #[error("Failed to fetch element from HashMap")]
    HashMapError,
}
