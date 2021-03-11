use crate::core::Error as CoreError;
use crate::relay::Error as RelayError;
use backoff::ExponentialBackoff;
use bitcoin::BitcoinError as BitcoinCoreError;
use bitcoin::Error as BitcoinError;
use jsonrpc_core_client::RpcError;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use parity_scale_codec::Error as CodecError;
use runtime::substrate_subxt::Error as XtError;
use runtime::Error as RuntimeError;
use std::net::AddrParseError;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal error")]
    InternalError,
    #[error("Could not verify that the oracle is offline")]
    CheckOracleOffline,
    #[error("Suggested status update does not contain block hash")]
    EventNoBlockHash,
    #[error("Error fetching transaction")]
    TransactionFetchingError,

    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("CoreError: {0}")]
    CoreError(#[from] CoreError<RelayError>),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("BitcoinCoreError: {0}")]
    BitcoinCoreError(#[from] BitcoinCoreError),
    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] JsonRpcError),
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Mathematical operation error")]
    MathError,
}

/// Gets the default retrying policy
pub fn get_retry_policy() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(24 * 60 * 60)),
        max_interval: Duration::from_secs(10 * 60), // wait at 10 minutes before retrying
        initial_interval: Duration::from_secs(1),
        current_interval: Duration::from_secs(1),
        multiplier: 2.0,            // delay doubles every time
        randomization_factor: 0.25, // random value between 25% below and 25% above the ideal delay
        ..Default::default()
    }
}
