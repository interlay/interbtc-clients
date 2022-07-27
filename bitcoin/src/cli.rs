#![cfg(feature = "cli")]

use crate::{BitcoinCore, BitcoinCoreBuilder, Error};
use bitcoincore_rpc::{bitcoin::Network, Auth};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
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

    /// Url of the electrs server. If unset, a default fallback
    /// is used depending on the detected network.
    #[clap(long)]
    pub electrs_url: Option<String>,
}

impl BitcoinOpts {
    fn new_auth(&self) -> Auth {
        Auth::UserPass(self.bitcoin_rpc_user.clone(), self.bitcoin_rpc_pass.clone())
    }

    fn new_client_builder(&self, wallet_name: Option<String>) -> BitcoinCoreBuilder {
        BitcoinCoreBuilder::new(self.bitcoin_rpc_url.clone())
            .set_auth(self.new_auth())
            .set_wallet_name(wallet_name)
            .set_electrs_url(self.electrs_url.clone())
    }

    pub async fn new_client(&self, wallet_name: Option<String>) -> Result<BitcoinCore, Error> {
        self.new_client_builder(wallet_name)
            .build_and_connect(Duration::from_millis(self.bitcoin_connection_timeout_ms))
            .await
    }

    pub fn new_client_with_network(&self, wallet_name: Option<String>, network: Network) -> Result<BitcoinCore, Error> {
        self.new_client_builder(wallet_name).build_with_network(network)
    }
}
