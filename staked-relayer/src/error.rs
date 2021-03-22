use crate::{core::Error as CoreError, relay::Error as RelayError};
use bitcoin::{BitcoinError as BitcoinCoreError, Error as BitcoinError};
use jsonrpc_core_client::RpcError;
use parity_scale_codec::Error as CodecError;
use runtime::{substrate_subxt::Error as SubxtError, Error as RuntimeError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not verify that the oracle is offline")]
    CheckOracleOffline,
    #[error("Suggested status update does not contain block hash")]
    EventNoBlockHash,
    #[error("Error fetching transaction")]
    TransactionFetchingError,
    #[error("Mathematical operation caused an overflow")]
    ArithmeticOverflow,
    #[error("Mathematical operation caused an underflow")]
    ArithmeticUnderflow,

    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
    #[error("SubxtError: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("CoreError: {0}")]
    CoreError(#[from] CoreError<RelayError>),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("BitcoinCoreError: {0}")]
    BitcoinCoreError(#[from] BitcoinCoreError),
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
}
