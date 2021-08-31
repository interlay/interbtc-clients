use crate::relay::Error as RelayError;
use bitcoin::Error as BitcoinError;
use hex::FromHexError;
use jsonrpc_core_client::RpcError;
use parity_scale_codec::Error as CodecError;
use runtime::{substrate_subxt::Error as SubxtError, CurrencyId, Error as RuntimeError};
use service::Error as ServiceError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Insufficient funds available")]
    InsufficientFunds,
    #[error("Value below dust amount")]
    BelowDustAmount,
    #[error("Failed to load or create bitcoin wallet: {0}")]
    WalletInitializationFailure(BitcoinError),
    #[error("Transaction contains more than one return-to-self uxto")]
    TooManyReturnToSelfAddresses,
    #[error("Mathematical operation caused an overflow")]
    ArithmeticOverflow,
    #[error("Mathematical operation caused an underflow")]
    ArithmeticUnderflow,
    #[error(transparent)]
    TryIntoIntError(#[from] std::num::TryFromIntError),
    #[error("Deadline has expired")]
    DeadlineExpired,
    #[error("Failed to parse argument; argument not valid")]
    ArgumentParsingError,
    #[error("Attempted to start vault with currency {0:?}, but it is already registered with currency {1:?}")]
    InvalidCurrency(CurrencyId, CurrencyId),

    #[error("ServiceError: {0}")]
    ServiceError(#[from] ServiceError),
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Hex conversion error: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubxtError: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
}
