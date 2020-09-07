use crate::rpc::Error as RpcError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to decode hash")]
    DecodeHash,
    #[error("Failed to serialize block header")]
    SerializeHeader,

    #[error("RpcError: {0}")]
    RpcError(#[from] RpcError),
}
