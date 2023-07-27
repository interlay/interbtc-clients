use crate::{BitcoinError, BitcoinLightError, ElectrsError};
use bitcoincore_rpc::{
    bitcoin::{
        address::Error as AddressError,
        consensus::encode::Error as BitcoinEncodeError,
        hashes::{hex::Error as HashHexError, Error as HashesError},
        key::Error as KeyError,
        secp256k1::Error as Secp256k1Error,
    },
    jsonrpc::{error::RpcError, Error as JsonRpcError},
};
use hex::FromHexError;
use serde_json::Error as SerdeJsonError;
use std::{io::Error as IoError, num::TryFromIntError, string::FromUtf8Error};
use thiserror::Error;
use tokio::time::error::Elapsed;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum KeyLoadingError {
    #[error("IoError: {0}")]
    IoError(#[from] IoError),
    #[error("FromUtf8Error: {0}")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("KeyError: {0}")]
    KeyError(#[from] KeyError),
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("BitcoinEncodeError: {0}")]
    BitcoinEncodeError(#[from] BitcoinEncodeError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("ConversionError: {0}")]
    ConversionError(#[from] ConversionError),
    #[error("Json error: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("Secp256k1Error: {0}")]
    Secp256k1Error(#[from] Secp256k1Error),
    #[error("KeyError: {0}")]
    KeyError(#[from] KeyError),
    #[error("Timeout: {0}")]
    TimeElapsed(#[from] Elapsed),
    #[error(transparent)]
    TryFromIntError(#[from] TryFromIntError),
    #[error("LightClientError: {0}")]
    LightClientError(#[from] BitcoinLightError),
    #[error("ElectrsError: {0}")]
    ElectrsError(#[from] ElectrsError),
    #[error("KeyLoadingError: {0}")]
    KeyLoadingError(#[from] KeyLoadingError),

    #[error("Connected to incompatible bitcoin core version: {0}")]
    IncompatibleVersion(usize),
    #[error("Could not confirm transaction")]
    ConfirmationError,
    #[error("Could not find block at height")]
    InvalidBitcoinHeight,
    #[error("Failed to sign transaction")]
    TransactionSigningError,
    #[error("Failed to obtain public key")]
    MissingPublicKey,
    #[error("Failed to connect")]
    ConnectionRefused,
    #[error("Wallet not found")]
    WalletNotFound,
    #[error("Invalid Bitcoin network")]
    InvalidBitcoinNetwork,
    #[error("Transaction contains more than one return-to-self utxo")]
    TooManyReturnToSelfAddresses,
    #[error("ArithmeticError")]
    ArithmeticError,
    #[error("MissingBitcoinFeeInfo")]
    MissingBitcoinFeeInfo,
    #[error("FailedToConstructWalletName")]
    FailedToConstructWalletName,
    #[error("AddressError: {0}")]
    AddressError(#[from] AddressError),
    #[error("Failed to fetch coinbase tx")]
    CoinbaseFetchingFailure,
}

impl Error {
    pub fn is_transport_error(&self) -> bool {
        matches!(
            self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Transport(_)))
        )
    }

    pub fn is_json_decode_error(&self) -> bool {
        matches!(self, Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Json(_))))
    }

    pub fn is_wallet_error(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcWalletError
        )
    }

    pub fn rejected_by_network_rules(&self) -> bool {
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcVerifyRejected
        )
    }

    /// Naming is intentionally somewhat unusual: RpcWalletError can also have other causes.
    pub fn could_be_insufficient_funds(&self) -> bool {
        // Regtest on bitcoind 0.22 gives "-4: insufficient funds", where -4 is RpcWalletError.
        // We additionally filter for RpcWalletInsufficientFunds because the name suggests
        // (and bitcoin source confirms) that some calls/versions will throw this error instead.
        // See e.g. https://github.com/bitcoin/bitcoin/blob/bd616bc16a3a7f70f60ca5034b5a91e5ac89ac9d/test/functional/interface_usdt_coinselection.py#L188
        matches!(self,
            Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcWalletError ||
                BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcWalletInsufficientFunds
        )
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
    #[error("HashHexError: {0}")]
    HashHexError(#[from] HashHexError),
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
