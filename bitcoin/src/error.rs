use crate::BitcoinError;
use bitcoincore_rpc::{
    bitcoin::{
        consensus::encode::Error as BitcoinEncodeError,
        hashes::Error as HashesError,
        secp256k1::Error as Secp256k1Error,
        util::{address::Error as AddressError, key::Error as KeyError},
    },
    jsonrpc::{error::RpcError, Error as JsonRpcError},
};
use hex::FromHexError;
use hyper::Error as HyperError;
use serde_json::Error as SerdeJsonError;
use std::io::ErrorKind as IoErrorKind;
use thiserror::Error;
use tokio::time::Elapsed;

#[derive(Error, Debug)]
pub enum Error {
    #[error("BitcoinEncodeError: {0}")]
    BitcoinEncodeError(#[from] BitcoinEncodeError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("ConversionError: {0}")]
    ConversionError(#[from] ConversionError),
    #[error("Error occurred in callback: {0}")]
    CallbackError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Json error: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("Secp256k1Error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),
    #[error("KeyError: {0}")]
    KeyError(#[from] KeyError),
    #[error("Timeout: {0}")]
    TimeElapsed(#[from] Elapsed),

    #[error("Could not confirm transaction")]
    ConfirmationError,
    #[error("Could not find block at height")]
    InvalidBitcoinHeight,
    #[error("Failed to sign transaction")]
    TransactionSigningError,
    #[error("Failed to parse transaction")]
    ParsingError,
    #[error("Failed to obtain public key")]
    MissingPublicKey,
    #[error("Failed to connect")]
    ConnectionRefused,
    #[error("Wallet not found")]
    WalletNotFound,
    #[error("Invalid Bitcoin network")]
    InvalidBitcoinNetwork,
}

impl Error {
    pub fn is_connection_refused(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Hyper(HyperError::Io(err))))
                if err.kind() == IoErrorKind::ConnectionRefused
        )
    }

    pub fn is_connection_aborted(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Hyper(HyperError::Io(err))))
                if err.kind() == IoErrorKind::ConnectionAborted
        )
    }

    pub fn is_json_decode_error(&self) -> bool {
        matches!(self, Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Json(_))))
    }

    pub fn is_wallet_not_found(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcWalletNotFound
        )
    }

    pub fn is_invalid_parameter(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcInvalidParameter
        )
    }
}

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("FromHexError: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("AddressError: {0}")]
    AddressError(#[from] AddressError),
    #[error("HashesError: {0}")]
    HashesError(#[from] HashesError),
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid payload")]
    InvalidPayload,
    #[error("Could not convert block hash")]
    BlockHashError,
}

// https://github.com/bitcoin/bitcoin/blob/be3af4f31089726267ce2dbdd6c9c153bb5aeae1/src/rpc/protocol.h#L43
#[derive(Debug, FromPrimitive, PartialEq, Eq)]
pub enum BitcoinRpcError {
    /// Standard JSON-RPC 2.0 errors
    RpcInvalidRequest = -32600,
    RpcMethodNotFound = -32601,
    RpcInvalidParams = -32602,
    RpcInternalError = -32603,
    RpcParseError = -32700,

    /// General application defined errors
    RpcMiscError = -1,
    RpcTypeError = -3,
    RpcInvalidAddressOrKey = -5,
    RpcOutOfMemory = -7,
    RpcInvalidParameter = -8,
    RpcDatabaseError = -20,
    RpcDeserializationErrr = -22,
    RpcVerifyError = -25,
    RpcVerifyRejected = -26,
    RpcVerifyAlreadyInChain = -27,
    RpcInWarmup = -28,
    RpcMethodDeprecated = -32,

    /// Aliases for backward compatibility
    // RpcTransactionError           = RpcVerifyError,
    // RpcTransactionRejected        = RpcVerifyRejected,
    // RpcTransactionAlreadyInChain  = RpcVerifyAlreadyInChain,

    /// P2P client errors
    RpcClientNotConnected = -9,
    RpcClientInInitialDownload = -10,
    RpcClientNodeAlreadyAdded = -23,
    RpcClientNodeNotAdded = -24,
    RpcClientNodeNotConnected = -29,
    RpcClientInvalidIpOrSubnet = -30,
    RpcClientP2PDisabled = -31,

    /// Chain errors
    RpcClientMempoolDisabled = -33,

    /// Wallet errors
    RpcWalletError = -4,
    RpcWalletInsufficientFunds = -6,
    RpcWalletInvalidLabelName = -11,
    RpcWalletKeypoolRanOut = -12,
    RpcWalletUnlockNeeded = -13,
    RpcWalletPassphraseIncorrect = -14,
    RpcWalletWrongEncState = -15,
    RpcWalletEncryptionFailed = -16,
    RpcWalletAlreadyUnlocked = -17,
    RpcWalletNotFound = -18,
    RpcWalletNotSpecified = -19,

    /// Backwards compatible aliases
    // RpcWalletInvalidAccountName = RpcWalletInvalidLabelName,

    /// Unused reserved codes.
    RpcForbiddenBySafeMode = -2,

    /// Unknown error code (not in spec).
    RpcUnknownError = 0,
}

impl From<RpcError> for BitcoinRpcError {
    fn from(err: RpcError) -> Self {
        match num::FromPrimitive::from_i32(err.code) {
            Some(err) => err,
            None => Self::RpcUnknownError,
        }
    }
}
