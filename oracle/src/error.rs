use reqwest::Error as ReqwestError;
use runtime::{substrate_subxt::Error as SubxtError, Error as RuntimeError};
use std::num::ParseIntError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid response")]
    InvalidResponse,
    #[error("Invalid exchange rate")]
    InvalidExchangeRate,
    #[error("Invalid fee estimate")]
    InvalidFeeEstimate,

    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubxtError: {0}")]
    SubxtError(#[from] SubxtError),
    #[error("ParseIntError: {0}")]
    ParseIntError(#[from] ParseIntError),
}
