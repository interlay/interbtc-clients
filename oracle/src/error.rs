#![allow(clippy::enum_variant_names)]

use crate::{
    currency::{Currency, CurrencyPair},
    feeds::FeedName,
};
use reqwest::Error as ReqwestError;
use runtime::{Error as RuntimeError, SubxtError};
use serde_json::Error as SerdeJsonError;
use std::{
    io::Error as IoError,
    num::{ParseFloatError, ParseIntError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError<Currency> {
    #[error("No start")]
    NoStart,
    #[error("No end")]
    NoEnd,
    #[error("No path from {0} to {1}")]
    NoPath(CurrencyPair<Currency>, CurrencyPair<Currency>),
}

#[derive(Error, Debug)]
#[error("{feed}: {pair} => {error}")]
pub struct PriceConfigError<Currency> {
    pub(crate) feed: FeedName,
    pub(crate) pair: CurrencyPair<Currency>,
    pub(crate) error: ConfigError<Currency>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Shutdown")]
    Shutdown,
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Invalid exchange rate")]
    InvalidExchangeRate,
    #[error("Invalid currency")]
    InvalidCurrency,
    #[error("Invalid config: {0}")]
    InvalidConfig(PriceConfigError<Currency>),
    #[error("{0} not configured")]
    NotConfigured(FeedName),
    #[error("Invalid dia symbol. Base must be USD & quote must be <symbol>=<id>. E.g. STDOT=Moonbeam/0xFA36Fe1dA08C89eC72Ea1F0143a35bFd5DAea108")]
    InvalidDiaSymbol,

    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubxtError: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("ParseFloatError: {0}")]
    ParseFloatError(#[from] ParseFloatError),
    #[error("SerdeJsonError: {0}")]
    SerdeJsonError(#[from] SerdeJsonError),
    #[error("IoError: {0}")]
    IoError(#[from] IoError),
}
