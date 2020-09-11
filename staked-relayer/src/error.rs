use crate::relay::Error as RelayError;
use crate::rpc::Error as RpcError;
use relayer_core::Error as CoreError;
use std::env::VarError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not start Bitcoin client")]
    BitcoinClient,
    #[error("Unknown status code")]
    UnknownStatusCode,
    #[error("Unknown error code")]
    UnknownErrorCode,

    #[error("Read env error: {0}: {1}")]
    ReadVar(String, VarError),
    #[error("RpcError: {0}")]
    RpcError(#[from] RpcError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("CoreError: {0}")]
    CoreError(#[from] CoreError<RelayError>),
}
