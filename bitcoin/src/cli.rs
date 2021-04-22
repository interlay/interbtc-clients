use crate::{BitcoinCore, Error};
use bitcoincore_rpc::{bitcoin::Network, Auth};
use clap::Clap;
use std::{str::FromStr, time::Duration};

#[derive(Debug, Copy, Clone)]
pub struct BitcoinNetwork(pub Network);

impl FromStr for BitcoinNetwork {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "mainnet" => Ok(BitcoinNetwork(Network::Bitcoin)),
            "testnet" => Ok(BitcoinNetwork(Network::Testnet)),
            "regtest" => Ok(BitcoinNetwork(Network::Regtest)),
            _ => Err(Error::InvalidBitcoinNetwork),
        }
    }
}

#[derive(Clap, Debug, Clone)]
pub struct BitcoinOpts {
    #[clap(long, env = "BITCOIN_RPC_URL")]
    pub bitcoin_rpc_url: String,

    #[clap(long, env = "BITCOIN_RPC_USER")]
    pub bitcoin_rpc_user: String,

    #[clap(long, env = "BITCOIN_RPC_PASS")]
    pub bitcoin_rpc_pass: String,

    /// Timeout in milliseconds to wait for connection to bitcoin-core.
    #[clap(long, default_value = "60000")]
    pub bitcoin_connection_timeout_ms: u64,

    /// Bitcoin network type for address encoding.
    #[clap(long, default_value = "regtest")]
    pub network: BitcoinNetwork,
}

impl BitcoinOpts {
    fn new_auth(&self) -> Auth {
        Auth::UserPass(self.bitcoin_rpc_user.clone(), self.bitcoin_rpc_pass.clone())
    }

    pub fn new_client(&self, wallet_name: Option<String>) -> Result<BitcoinCore, Error> {
        BitcoinCore::new(
            self.bitcoin_rpc_url.clone(),
            self.new_auth(),
            wallet_name,
            self.network.0,
            Duration::from_millis(self.bitcoin_connection_timeout_ms),
        )
    }
}
