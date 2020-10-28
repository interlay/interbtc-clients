use jsonrpsee::transport::ws::WsNewDnsError;
use parity_scale_codec::Error as CodecError;
use serde_json::Error as SerdeJsonError;
use std::array::TryFromSliceError;
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
    /// Occurs during websocket handshake
    #[error("Rpc error: {0}")]
    WsHandshake(#[from] WsNewDnsError),
}
