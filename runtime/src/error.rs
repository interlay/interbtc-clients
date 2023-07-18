pub use jsonrpsee::core::Error as JsonRpseeError;

use crate::{types::*, BTC_RELAY_MODULE, ISSUE_MODULE, SYSTEM_MODULE, VAULT_REGISTRY_MODULE};
use codec::Error as CodecError;
use jsonrpsee::{
    client_transport::ws::WsHandshakeError,
    types::error::{CallError, ErrorObjectOwned},
};
use prometheus::Error as PrometheusError;
use serde_json::Error as SerdeJsonError;
use sp_core::crypto::SecretStringError;
use std::{array::TryFromSliceError, fmt::Debug, io::Error as IoError, num::TryFromIntError, str::Utf8Error};
use subxt::error::{DispatchError, TransactionError};
pub use subxt::{error::RpcError, Error as SubxtError};
use thiserror::Error;
use tokio::time::error::Elapsed;
use url::ParseError as UrlParseError;

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
    #[error("Could not unlock local asset registry")]
    CannotOpenAssetRegistry,
    #[error("Cannot acquire lock for lending assets")]
    CannotAccessLendingAssets,
    #[error("Could not get vault")]
    VaultNotFound,
    #[error("Vault has been liquidated")]
    VaultLiquidated,
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
    #[error("Operation not supported on token variant")]
    TokenUnsupported,

    #[error("Client does not support spec_version: expected {0}..{1}, got {2}")]
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
    // TODO: implement Display
    #[error("BitcoinError: {0}")]
    BitcoinError(String),
}

impl From<module_bitcoin::Error> for Error {
    fn from(value: module_bitcoin::Error) -> Self {
        Self::BitcoinError(format!("{value:?}"))
    }
}

impl Error {
    pub fn is_any_module_err(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(SubxtError::Runtime(DispatchError::Module(_))),
        )
    }

    fn is_module_err(&self, pallet_name: &str, error_name: &str) -> bool {
        if let Error::SubxtRuntimeError(SubxtError::Runtime(DispatchError::Module(module_error))) = self {
            if let Ok(details) = module_error.details() {
                return details.pallet.name() == pallet_name && details.variant.name == error_name;
            }
        }
        false
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

    pub fn is_threshold_not_set(&self) -> bool {
        self.is_module_err(
            VAULT_REGISTRY_MODULE,
            &format!("{:?}", VaultRegistryPalletError::ThresholdNotSet),
        )
    }

    fn map_custom_error<T>(&self, call: impl Fn(&ErrorObjectOwned) -> Option<T>) -> Option<T> {
        if let Error::SubxtRuntimeError(SubxtError::Rpc(RpcError::ClientError(e))) = self {
            match e.downcast_ref::<JsonRpseeError>() {
                Some(e) => match e {
                    JsonRpseeError::Call(CallError::Custom(err)) => call(err),
                    _ => None,
                },
                None => {
                    log::error!("Failed to downcast RPC error; this is a bug please file an issue");
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn is_invalid_transaction(&self) -> Option<String> {
        self.map_custom_error(|custom_error| {
            if custom_error.code() == POOL_INVALID_TX {
                Some(custom_error.data().map(ToString::to_string).unwrap_or_default())
            } else {
                None
            }
        })
    }

    pub fn is_pool_too_low_priority(&self) -> Option<()> {
        self.map_custom_error(|custom_error| {
            if custom_error.code() == POOL_TOO_LOW_PRIORITY {
                Some(())
            } else {
                None
            }
        })
    }

    pub fn is_rpc_disconnect_error(&self) -> bool {
        match self {
            Error::SubxtRuntimeError(SubxtError::Rpc(RpcError::ClientError(e))) => {
                match e.downcast_ref::<JsonRpseeError>() {
                    Some(e) => matches!(e, JsonRpseeError::RestartNeeded(_)),
                    None => {
                        log::error!("Failed to downcast RPC error; this is a bug please file an issue");
                        false
                    }
                }
            }
            Error::SubxtRuntimeError(SubxtError::Rpc(RpcError::SubscriptionDropped)) => true,
            _ => false,
        }
    }

    pub fn is_rpc_error(&self) -> bool {
        matches!(self, Error::SubxtRuntimeError(SubxtError::Rpc(_)))
    }

    pub fn is_block_hash_not_found_error(&self) -> bool {
        matches!(
            self,
            Error::SubxtRuntimeError(SubxtError::Transaction(TransactionError::BlockNotFound))
        )
    }

    pub fn is_ws_invalid_url_error(&self) -> bool {
        if let Error::SubxtRuntimeError(SubxtError::Rpc(RpcError::ClientError(e))) = self {
            match e.downcast_ref::<JsonRpseeError>() {
                Some(e) => {
                    return matches!(
                        e,
                    JsonRpseeError::Transport(err)
                        if matches!(err.downcast_ref::<WsHandshakeError>(), Some(WsHandshakeError::Url(_)))
                    )
                }
                None => {
                    log::error!("Failed to downcast RPC error; this is a bug please file an issue");
                }
            }
        }

        false
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
