use parity_scale_codec::Error as CodecError;
use std::array::TryFromSliceError;
use std::num::TryFromIntError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not get exchange rate info")]
    ExchangeRateInfo,
    #[error("Could not verify that the oracle is offline")]
    CheckOracleOffline,

    #[error("Error serializing: {0}")]
    Serialize(#[from] TryFromSliceError),
    #[error("Error converting: {0}")]
    Convert(#[from] TryFromIntError),
    #[error("Error communicating with parachain: {0}")]
    XtError(#[from] XtError),
    #[error("Error decoding: {0}")]
    CodecError(#[from] CodecError),
}
