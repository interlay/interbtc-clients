use bitcoin::Error as BitcoinError;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use parity_scale_codec::Error as CodecError;
use runtime::{substrate_subxt::Error as XtError, Error as RuntimeError};
use serde_json::Error as SerdeJsonError;
use sp_core::crypto::SecretStringError;
use std::io::Error as IoError;
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Insufficient funds available")]
    InsufficientFunds,
    #[error("Open time inconsistent with chain height")]
    InvalidOpenTime,
    #[error("Channel unexpectedly closed")]
    ChannelClosed,
    #[error("Invalid Bitcoin network")]
    InvalidBitcoinNetwork,
    #[error("Expected blocks but got none")]
    NoIncomingBlocks,
    #[error("Failed to load or create bitcoin wallet: {0}")]
    WalletInitializationFailure(BitcoinError),

    #[error("Failed to load credentials from file: {0}")]
    KeyLoadingFailure(#[from] KeyLoadingError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] JsonRpcError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
}

#[derive(Error, Debug)]
pub enum KeyLoadingError {
    #[error("Key not found in file")]
    KeyNotFound,
    #[error("Json parsing error: {0}")]
    JsonError(#[from] SerdeJsonError),
    #[error("Io error: {0}")]
    IoError(#[from] IoError),
    #[error("Invalid secret string: {0:?}")]
    SecretStringError(SecretStringError),
}
