pub use jsonrpsee::core::Error as JsonRpseeError;

use crate::{metadata::DispatchError, types::*, BTC_RELAY_MODULE, ISSUE_MODULE, RELAY_MODULE, SYSTEM_MODULE};
use codec::Error as CodecError;
use jsonrpsee::{client_transport::ws::WsHandshakeError, core::error::Error as RequestError, types::error::CallError};
use prometheus::Error as PrometheusError;
use serde_json::Error as SerdeJsonError;
use std::{array::TryFromSliceError, fmt::Debug, io::Error as IoError, num::TryFromIntError, str::Utf8Error};
use subxt::{sp_core::crypto::SecretStringError, BasicError, ModuleError, TransactionError};
use thiserror::Error;
use tokio::time::error::Elapsed;
use url::ParseError as UrlParseError;
pub type SubxtError = subxt::Error<DispatchError>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not get exchange rate info")]
    ExchangeRateInfo,
    #[error("Could not get issue id")]
    RequestIssueIDNotFound,
    #[error("Could not get redeem id")]
    RequestRedeemIDNotFound,
    #[error("Could not get replace id")]
    RequestReplaceIDNotFound,
    #[error("Could not get block")]
    BlockNotFound,
    #[error("Could not get foreign asset")]
    AssetNotFound,
    #[error("Could not get vault")]
    VaultNotFound,
    #[error("Vault has been liquidated")]
    VaultLiquidated,
    #[error("Vault has stolen BTC")]
    VaultCommittedTheft,
    #[error("Channel closed unexpectedly")]
    ChannelClosed,
    #[error("Cannot replace existing transaction")]
    PoolTooLowPriority,
    #[error("Transaction did not get included - block hash not found")]
    BlockHashNotFound,
    #[error("Transaction is invalid: {0}")]
    InvalidTransaction(String),
    #[error("Request has timed out")]
    Timeout,
    #[error("Block is not in the relay main chain")]
    BlockNotInRelayMainChain,
    #[error("Invalid currency")]
    InvalidCurrency,
    #[error("Invalid keyring arguments")]
    KeyringArgumentError,
    #[error("Failed to parse keyring account")]
    KeyringAccountParsingError,
    #[error("Storage item not found")]
    StorageItemNotFound,
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Currency not found")]
    CurrencyNotFound,
    #[error("Client does not support spec_version: expected {0}..={1}, got {2}")]
    InvalidSpecVersion(u32, u32, u32),
    #[error("Client metadata is different from parachain metadata: expected {0}, got {1}")]
    ParachainMetadataMismatch(String, String),
    #[error("Specified Bitcoin network differs from the one on the parachain: expected {0}, got {1}")]
    BitcoinNetworkMismatch(String, String),
    #[error("Failed to load credentials from file: {0}")]
    KeyLoadingFailure(#[from] KeyLoadingError),
    #[error("Error serializing: {0}")]
    Serialize(#[from] TryFromSliceError),
    #[error("Error converting: {0}")]
    Convert(#[from] TryFromIntError),
    #[error("Subxt runtime error: {0}")]
    SubxtRuntimeError(#[from] SubxtError),
    #[error("Error decoding: {0}")]
    CodecError(#[from] CodecError),
    #[error("Error encoding json data: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("Error getting json-rpsee data: {0}")]
    JsonRpseeError(#[from] JsonRpseeError),
    #[error("Timeout: {0}")]
    TimeElapsed(#[from] Elapsed),
    #[error("UrlParseError: {0}")]
    UrlParseError(#[from] UrlParseError),
    #[error("PrometheusError: {0}")]
    PrometheusError(#[from] PrometheusError),
    #[error("Utf8Error: {0}")]
    Utf8Error(#[from] Utf8Error),
}

impl From<BasicError> for Error {
    fn from(err: BasicError) -> Self {
        Self::SubxtRuntimeError(err.into())
    }
}

impl Error {
    fn is_module_err(&self, pallet_name: &str, error_name: &str) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(SubxtError::Module(ModuleError {
                pallet, error, ..
            })) if pallet == pallet_name && error == error_name,
        )
    }

    pub fn is_duplicate_block(&self) -> bool {
        self.is_module_err(BTC_RELAY_MODULE, &format!("{:?}", BtcRelayPalletError::DuplicateBlock))
    }

    pub fn is_invalid_chain_id(&self) -> bool {
        self.is_module_err(BTC_RELAY_MODULE, &format!("{:?}", BtcRelayPalletError::InvalidChainID))
    }

    pub fn is_issue_completed(&self) -> bool {
        self.is_module_err(ISSUE_MODULE, &format!("{:?}", IssuePalletError::IssueCompleted))
    }

    fn map_call_error<T>(&self, call: impl Fn(&CallError) -> Option<T>) -> Option<T> {
        match self {
            Error::SubxtRuntimeError(SubxtError::Rpc(RequestError::Call(err))) => call(err),
            _ => None,
        }
    }

    pub fn is_invalid_transaction(&self) -> Option<String> {
        self.map_call_error(|call_error| {
            if let CallError::Custom {
                code: POOL_INVALID_TX,
                data,
                ..
            } = call_error
            {
                Some(data.clone().map(|raw| raw.to_string()).unwrap_or_default())
            } else {
                None
            }
        })
    }

    pub fn is_pool_too_low_priority(&self) -> Option<()> {
        self.map_call_error(|call_error| {
            if let CallError::Custom {
                code: POOL_TOO_LOW_PRIORITY,
                ..
            } = call_error
            {
                Some(())
            } else {
                None
            }
        })
    }

    pub fn is_rpc_disconnect_error(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(SubxtError::Rpc(JsonRpseeError::RestartNeeded(_)))
        )
    }

    pub fn is_rpc_error(&self) -> bool {
        matches!(self, Error::SubxtRuntimeError(SubxtError::Rpc(_)))
    }

    pub fn is_block_hash_not_found_error(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(SubxtError::Transaction(TransactionError::BlockHashNotFound))
        )
    }

    pub fn is_ws_invalid_url_error(&self) -> bool {
        matches!(
            self,
            Error::JsonRpseeError(JsonRpseeError::Transport(err))
            if matches!(err.downcast_ref::<WsHandshakeError>(), Some(WsHandshakeError::Url(_)))
        )
    }

    pub fn is_parachain_shutdown_error(&self) -> bool {
        self.is_module_err(SYSTEM_MODULE, &format!("{:?}", SystemPalletError::CallFiltered))
    }
}

#[derive(Error, Debug)]
pub enum KeyLoadingError {
    #[error("Key not found in file")]
    KeyNotFound,
    #[error("Json parsing error: {0}")]
    JsonError(#[from] SerdeJsonError),
    #[error("Io error: {0}")]
    IoError(#[from] IoError),
    #[error("Invalid secret string: {0:?}")]
    SecretStringError(SecretStringError),
}

// https://github.com/paritytech/substrate/blob/e60597dff0aa7ffad623be2cc6edd94c7dc51edd/client/rpc-api/src/author/error.rs#L80
const BASE_ERROR: i32 = 1000;
const POOL_INVALID_TX: i32 = BASE_ERROR + 10;
const POOL_TOO_LOW_PRIORITY: i32 = POOL_INVALID_TX + 4;
