use runtime::{substrate_subxt::Error as XtError, Error as RuntimeError};
use thiserror::Error;
use coingecko::Error as CoinGeckoError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid exchange rate")]
    InvalidExchangeRate,

    #[error("CoinGeckoError: {0}")]
    CoinGeckoError(#[from] CoinGeckoError),
    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
}
