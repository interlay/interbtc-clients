use crate::{core::Error as CoreError, relay::Error as RelayError};
use bitcoin::{BitcoinError as BitcoinCoreError, Error as BitcoinError};
use jsonrpc_core_client::RpcError;
use runtime::{substrate_subxt::Error as SubxtError, Error as RuntimeError};
use service::Error as ServiceError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ServiceError: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
    #[error("SubxtError: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("CoreError: {0}")]
    CoreError(#[from] CoreError<RelayError>),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("BitcoinCoreError: {0}")]
    BitcoinCoreError(#[from] BitcoinCoreError),
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
}
