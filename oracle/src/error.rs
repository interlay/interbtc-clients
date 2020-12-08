use reqwest::Error as ReqwestError;
use runtime::{substrate_subxt::Error as XtError, Error as RuntimeError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid exchange rate")]
    InvalidExchangeRate,

    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] ReqwestError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
}
