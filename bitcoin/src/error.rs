use crate::BitcoinError;
use bitcoincore_rpc::bitcoin::util::address::Error as AddressError;
use hex::FromHexError;
use std::env::VarError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Read env error: {0}: {1}")]
    ReadVar(String, VarError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
    #[error("ConversionError: {0}")]
    ConversionError(#[from] ConversionError),
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
