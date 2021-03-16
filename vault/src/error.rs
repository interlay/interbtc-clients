use bitcoin::Error as BitcoinError;
use hex::FromHexError;
use jsonrpc_core_client::RpcError;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use parity_scale_codec::Error as CodecError;
use runtime::{substrate_subxt::Error as XtError, Error as RuntimeError};
use std::net::AddrParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Internal error")]
    InternalError,
    #[error("Insufficient funds available")]
    InsufficientFunds,
    #[error("Open time inconsistent with chain height")]
    InvalidOpenTime,
    #[error("Channel unexpectedly closed")]
    ChannelClosed,
    #[error("Invalid Bitcoin network")]
    InvalidBitcoinNetwork,
    #[error("Expected blocks but got none")]
    NoIncomingBlocks,
    #[error("Failed to load or create bitcoin wallet: {0}")]
    WalletInitializationFailure(BitcoinError),
    #[error("Transaction contains more than one return-to-self uxto")]
    TooManyReturnToSelfAddresses,
    #[error("Mathematical operation caused an overflow")]
    ArithmeticOverflow,
    #[error("Mathematical operation caused an underflow")]
    ArithmeticUnderflow,
    #[error("Mathematical operation error")]
    MathError,
    #[error("Vault has uncompleted redeem requests")]
    UncompletedRedeemRequests,

    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
    #[error("Hex conversion error: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("JsonRpcError: {0}")]
    JsonRpcError(#[from] JsonRpcError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
}
