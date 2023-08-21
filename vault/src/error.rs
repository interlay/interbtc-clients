use bitcoin::Error as BitcoinError;
use jsonrpc_core_client::RpcError;
use parity_scale_codec::Error as CodecError;
use rocksdb::Error as RocksDbError;
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, num::ParseIntError, string::FromUtf8Error};
use thiserror::Error;
use tokio::task::JoinError as TokioJoinError;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Insufficient funds available")]
    InsufficientFunds,
    #[error("Failed to load or create bitcoin wallet: {0}")]
    WalletInitializationFailure(BitcoinError),
    #[error("Mathematical operation caused an overflow")]
    ArithmeticOverflow,
    #[error("Mathematical operation caused an underflow")]
    ArithmeticUnderflow,
    #[error(transparent)]
    TryIntoIntError(#[from] std::num::TryFromIntError),
    #[error("Deadline has expired")]
    DeadlineExpired,
    #[error("Faucet url not set")]
    FaucetUrlNotSet,
    #[error("Faucet allowance for `{0}` not set")]
    FaucetAllowanceNotSet(String),

    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("DatabaseError: {0}")]
    DatabaseError(#[from] RocksDbError),
    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("FromUtf8Error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("BroadcastStreamRecvError: {0}")]
    BroadcastStreamRecvError(#[from] BroadcastStreamRecvError),
    #[error("Client has shutdown")]
    ClientShutdown,
    #[error("OsString parsing error")]
    OsStringError,
    #[error("File already exists")]
    FileAlreadyExists,
    #[error("There is a services already running on the system, with pid {0}")]
    ServiceAlreadyRunning(u32),
    #[error("Process with pid {0} not found")]
    ProcessNotFound(String),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("TokioError: {0}")]
    TokioError(#[from] TokioJoinError),
    #[error("System I/O error: {0}")]
    IoError(#[from] IoError),
}

impl Error {
    pub fn to_human(self) -> String {
        match self {
            Self::RuntimeError(runtime_error) => runtime_error.to_human(),
            err => err.to_string(),
        }
    }
}

impl From<backoff::Error<Error>> for Error {
    fn from(err: backoff::Error<Error>) -> Self {
        match err {
            backoff::Error::Permanent(err) => err,
            backoff::Error::Transient(err) => err,
        }
    }
}
