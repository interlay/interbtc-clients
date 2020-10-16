use crate::relay::Error as RelayError;
use bitcoin::Error as BitcoinError;
use parity_scale_codec::Error as CodecError;
use relayer_core::bitcoin::bitcoincore_rpc::Error as BtcRpcError;
use relayer_core::Error as CoreError;
use runtime::Error as RuntimeError;
use serde_json::Error as SerdeError;
use std::net::AddrParseError;
use substrate_subxt::Error as XtError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not verify that the oracle is offline")]
    CheckOracleOffline,
    #[error("JSON-RPC method expected input parameter")]
    ParamNotFound,
    #[error("Suggested status update does not contain block hash")]
    EventNoBlockHash,

    #[error("RuntimeError: {0}")]
    RuntimeError(#[from] RuntimeError),
    #[error("BtcRpcError: {0}")]
    BtcRpcError(#[from] BtcRpcError),
    #[error("RelayError: {0}")]
    RelayError(#[from] RelayError),
    #[error("SubXtError: {0}")]
    SubXtError(#[from] XtError),
    #[error("CoreError: {0}")]
    CoreError(#[from] CoreError<RelayError>),
    #[error("AddrParseError: {0}")]
    AddrParseError(#[from] AddrParseError),
    #[error("SerdeError: {0}")]
    SerdeError(#[from] SerdeError),
    #[error("CodecError: {0}")]
    CodecError(#[from] CodecError),
    #[error("BitcoinError: {0}")]
    BitcoinError(#[from] BitcoinError),
}
