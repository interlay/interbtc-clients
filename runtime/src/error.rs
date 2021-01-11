use jsonrpsee::{client::RequestError as JsonRPSeeError, transport::ws::WsNewDnsError};
use parity_scale_codec::Error as CodecError;
use serde_json::Error as SerdeJsonError;
use sp_core::crypto::SecretStringError;
use std::array::TryFromSliceError;
use std::io::Error as IoError;
use std::num::TryFromIntError;
pub use substrate_subxt::Error as XtError;
use thiserror::Error;

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
    #[error("Callback error: {0}")]
    CallbackError(Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to load credentials from file: {0}")]
    KeyLoadingFailure(#[from] KeyLoadingError),
    #[error("Channel unexpectedly closed")]
    ChannelClosed,
    #[error("Error serializing: {0}")]
    Serialize(#[from] TryFromSliceError),
    #[error("Error converting: {0}")]
    Convert(#[from] TryFromIntError),
    #[error("Error communicating with parachain: {0}")]
    XtError(#[from] XtError),
    #[error("Error decoding: {0}")]
    CodecError(#[from] CodecError),
    #[error("Error encoding json data: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("Error getting json-rpsee data: {0}")]
    JsonRPSeeError(#[from] JsonRPSeeError),
    /// Occurs during websocket handshake
    #[error("Rpc error: {0}")]
    WsHandshake(#[from] WsNewDnsError),
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
