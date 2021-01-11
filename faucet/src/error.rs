use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use parity_scale_codec::Error as CodecError;
use runtime::Error as RuntimeError;
use std::net::AddrParseError;
use thiserror::Error;
use kv::Error as KVError;

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
    #[error("Too many faucet requests")]
    FaucetOveruseError,
}
