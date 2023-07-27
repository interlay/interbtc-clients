use bitcoincore_rpc::bitcoin::{
    address::Error as BitcoinAddressError, consensus::encode::Error as BitcoinEncodeError,
    hashes::hex::Error as HexError,
};
use reqwest::{Error as ReqwestError, StatusCode};
use serde_json::Error as SerdeJsonError;
use std::num::{ParseIntError, TryFromIntError};
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("No previous output for input")]
    NoPrevOut,
    #[error("Cannot construct address")]
    InvalidAddress,

    #[error("BitcoinAddressError: {0}")]
    BitcoinAddressError(#[from] BitcoinAddressError),
    #[error("BitcoinEncodeError: {0}")]
    BitcoinEncodeError(#[from] BitcoinEncodeError),

    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("ParseError: {0}")]
    ParseError(#[from] ParseError),

    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),

    #[error("HexError: {0}")]
    HexError(#[from] HexError),

    #[error("TryFromIntError: {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),

    #[error("No txids in block")]
    EmptyBlock,
}

impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::ReqwestError(err) if err.status().contains(&StatusCode::NOT_FOUND))
    }
}
