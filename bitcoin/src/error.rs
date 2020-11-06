use crate::BitcoinError;
use bitcoincore_rpc::bitcoin::util::address::Error as AddressError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("ConversionError: {0}")]
    ConversionError(#[from] ConversionError),
    #[error("Could not confirm transaction")]
    ConfirmationError,
}

#[derive(Error, Debug)]
pub enum ConversionError {
    #[error("FromHexError: {0}")]
    FromHexError(#[from] FromHexError),
    #[error("AddressError: {0}")]
    AddressError(#[from] AddressError),
    #[error("Witness program error")]
    WitnessProgramError,
    #[error("Could not convert block hash")]
    BlockHashError,
}
