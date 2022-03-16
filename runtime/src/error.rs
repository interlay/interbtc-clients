pub use jsonrpsee::core::Error as JsonRpseeError;

use crate::{
    metadata::{DispatchError, ErrorDetails},
    types::*,
    BTC_RELAY_MODULE, ISSUE_MODULE, REDEEM_MODULE, RELAY_MODULE, SYSTEM_MODULE,
};
use codec::Error as CodecError;
use jsonrpsee::{
    client_transport::ws::WsHandshakeError,
    core::error::Error as RequestError,
    types::error::{CallError, ErrorResponse},
};
use prometheus::Error as PrometheusError;
use serde_json::Error as SerdeJsonError;
use std::{
    array::TryFromSliceError,
    fmt::{Debug, Display},
    io::Error as IoError,
    num::TryFromIntError,
};
use subxt::{sp_core::crypto::SecretStringError, BasicError};
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
    #[error("Client does not support spec_version: expected {0}, got {1}")]
    InvalidSpecVersion(u32, u32),
    #[error("Failed to load credentials from file: {0}")]
    KeyLoadingFailure(#[from] KeyLoadingError),
    #[error("Error serializing: {0}")]
    Serialize(#[from] TryFromSliceError),
    #[error("Error converting: {0}")]
    Convert(#[from] TryFromIntError),
    #[error("Subxt basic error: {0}")]
    SubxtBasicError(#[from] BasicError),
    #[error("Subxt runtime error: {0}")]
    SubxtRuntimeError(#[from] OuterSubxtError),
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
}

impl From<SubxtError> for Error {
    fn from(err: SubxtError) -> Self {
        Self::SubxtRuntimeError(OuterSubxtError(err))
    }
}

// hacky workaround to pretty print runtime errors
#[derive(Debug)]
pub struct OuterSubxtError(pub SubxtError);

impl From<SubxtError> for OuterSubxtError {
    fn from(err: SubxtError) -> Self {
        Self(err)
    }
}

impl std::error::Error for OuterSubxtError {}

impl Display for OuterSubxtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            subxt::Error::Runtime(err) => {
                if let Some(ErrorDetails { error, pallet, .. }) = err.clone().inner().details() {
                    write!(f, "{} from {}", error, pallet)
                } else {
                    Debug::fmt(&err, f)
                }
            }
            err => Display::fmt(&err, f),
        }
    }
}

impl Error {
    fn is_runtime_err(&self, pallet_name: &str, error_name: &str) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(OuterSubxtError(SubxtError::Runtime(runtime_error)))
            if matches!(
                runtime_error.clone().inner().details(),
                Some(ErrorDetails {
                    pallet,
                    error,
                    ..
                })
                if pallet == pallet_name && error == error_name
            )
        )
    }

    pub fn is_duplicate_block(&self) -> bool {
        self.is_runtime_err(BTC_RELAY_MODULE, &format!("{:?}", BtcRelayPalletError::DuplicateBlock))
    }

    pub fn is_invalid_chain_id(&self) -> bool {
        self.is_runtime_err(BTC_RELAY_MODULE, &format!("{:?}", BtcRelayPalletError::InvalidChainID))
    }

    pub fn is_issue_completed(&self) -> bool {
        self.is_runtime_err(ISSUE_MODULE, &format!("{:?}", IssuePalletError::IssueCompleted))
    }

    pub fn is_valid_refund(&self) -> bool {
        self.is_runtime_err(RELAY_MODULE, &format!("{:?}", RelayPalletError::ValidRefundTransaction))
    }

    fn map_call_error<T>(
        &self,
        call: impl Fn(&CallError) -> Option<T>,
        other: impl Fn(&String) -> Option<T>,
    ) -> Option<T> {
        match self {
            Error::SubxtRuntimeError(OuterSubxtError(SubxtError::Rpc(RequestError::Call(err)))) => call(err),
            Error::SubxtBasicError(BasicError::Rpc(RequestError::Request(message))) => {
                if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(message) {
                    call(&CallError::Custom {
                        code: error_response.error.code.code(),
                        message: error_response.error.message.to_string(),
                        data: error_response.error.data.map(ToOwned::to_owned),
                    })
                } else {
                    other(message)
                }
            }
            _ => None,
        }
    }

    pub fn is_invalid_transaction(&self) -> Option<String> {
        self.map_call_error(
            |call_error| {
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
            },
            |message| {
                if message.contains(INVALID_TX_MESSAGE) {
                    Some(message.to_string())
                } else {
                    None
                }
            },
        )
    }

    pub fn is_pool_too_low_priority(&self) -> Option<()> {
        self.map_call_error(
            |call_error| {
                if let CallError::Custom {
                    code: POOL_TOO_LOW_PRIORITY,
                    ..
                } = call_error
                {
                    Some(())
                } else {
                    None
                }
            },
            |message| {
                if message.contains(TOO_LOW_PRIORITY_MESSAGE) {
                    Some(())
                } else {
                    None
                }
            },
        )
    }

    pub fn is_commit_period_expired(&self) -> bool {
        self.is_runtime_err(REDEEM_MODULE, &format!("{:?}", RedeemPalletError::CommitPeriodExpired))
    }

    pub fn is_rpc_disconnect_error(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(OuterSubxtError(SubxtError::Rpc(JsonRpseeError::RestartNeeded(_))))
                | Error::SubxtBasicError(BasicError::Rpc(JsonRpseeError::RestartNeeded(_)))
        )
    }

    pub fn is_rpc_error(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(OuterSubxtError(SubxtError::Rpc(_))) | Error::SubxtBasicError(BasicError::Rpc(_))
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
        self.is_runtime_err(SYSTEM_MODULE, &format!("{:?}", SystemPalletError::CallFiltered))
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

const INVALID_TX_MESSAGE: &str = "Invalid Transaction";
const TOO_LOW_PRIORITY_MESSAGE: &str = "Priority is too low";
