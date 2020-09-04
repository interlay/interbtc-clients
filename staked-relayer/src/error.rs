use crate::rpc::Error as RpcError;
use std::env::VarError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not start Bitcoin client")]
    BitcoinClient,
    #[error("Read env error: {0}: {1}")]
    ReadVar(String, VarError),
    #[error("RpcError: {0}")]
    RpcError(#[from] RpcError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("Other: {0}")]
    Other(String),
}
