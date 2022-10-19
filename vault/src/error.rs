use bitcoin::Error as BitcoinError;
use jsonrpc_core_client::RpcError;
use parity_scale_codec::Error as CodecError;
use runtime::Error as RuntimeError;
use thiserror::Error;
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

    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("BroadcastStreamRecvError: {0}")]
    BroadcastStreamRecvError(#[from] BroadcastStreamRecvError),
}

impl From<Error> for service::Error<Error> {
    fn from(err: Error) -> Self {
        Self::Retry(err)
    }
}
