pub use jsonrpsee_types::error::Error as JsonRpseeError;
pub use substrate_subxt::Error as SubxtError;

use crate::{BTC_RELAY_MODULE, DUPLICATE_BLOCK_ERROR, ISSUE_COMPLETED_ERROR, ISSUE_MODULE};
use jsonrpsee_ws_client::transport::WsConnectError;
use parity_scale_codec::Error as CodecError;
use serde_json::Error as SerdeJsonError;
use sp_core::crypto::SecretStringError;
use std::{array::TryFromSliceError, io::Error as IoError, num::TryFromIntError};
use substrate_subxt::{ModuleError as SubxtModuleError, RuntimeError as SubxtRuntimeError};
use thiserror::Error;
use tokio::time::Elapsed;
use url::ParseError as UrlParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not get exchange rate info")]
    ExchangeRateInfo,
    #[error("Could not get issue id")]
    RequestIssueIDNotFound,
    #[error("Could not get redeem id")]
    RequestRedeemIDNotFound,
    #[error("Could not get replace id")]
    RequestReplaceIDNotFound,
    #[error("Could not get block")]
    BlockNotFound,
    #[error("Could not get vault")]
    VaultNotFound,
    #[error("Vault has been liquidated")]
    VaultLiquidated,
    #[error("Vault has stolen BTC")]
    VaultCommittedTheft,
    #[error("Channel closed unexpectedly")]
    ChannelClosed,
    #[error("Client has shutdown unexpectedly")]
    ClientShutdown,
    #[error("Transaction is outdated")]
    OutdatedTransaction,

    #[error("Failed to load credentials from file: {0}")]
    KeyLoadingFailure(#[from] KeyLoadingError),
    #[error("Error serializing: {0}")]
    Serialize(#[from] TryFromSliceError),
    #[error("Error converting: {0}")]
    Convert(#[from] TryFromIntError),
    #[error("Error communicating with parachain: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("Error decoding: {0}")]
    CodecError(#[from] CodecError),
    #[error("Error encoding json data: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("Error getting json-rpsee data: {0}")]
    JsonRpseeError(#[from] JsonRpseeError),
    /// Occurs during websocket handshake
    #[error("Rpc error: {0}")]
    WsConnectError(#[from] WsConnectError),
    #[error("Timeout: {0}")]
    TimeElapsed(#[from] Elapsed),
    #[error("UrlParseError: {0}")]
    UrlParseError(#[from] UrlParseError),

    /// Other error
    #[error("Other: {0}")]
    Other(String),
}

impl Error {
    pub fn is_issue_completed(&self) -> bool {
        matches!(self,
            Error::SubxtError(SubxtError::Runtime(SubxtRuntimeError::Module(SubxtModuleError {
                ref module,
                ref error,
            }))) if module == ISSUE_MODULE && error == ISSUE_COMPLETED_ERROR
        )
    }

    pub fn is_duplicate_block(&self) -> bool {
        matches!(self,
            Error::SubxtError(SubxtError::Runtime(SubxtRuntimeError::Module(SubxtModuleError {
                ref module,
                ref error,
            }))) if module == BTC_RELAY_MODULE && error == DUPLICATE_BLOCK_ERROR
        )
    }
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

// https://github.com/paritytech/substrate/blob/e60597dff0aa7ffad623be2cc6edd94c7dc51edd/client/rpc-api/src/author/error.rs#L80
const BASE_ERROR: i64 = 1000;
pub const POOL_INVALID_TX: i64 = BASE_ERROR + 10;
