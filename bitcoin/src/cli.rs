#![cfg(feature = "cli")]

use crate::{BitcoinCore, BitcoinCoreBuilder, BitcoinLight, Error};
use bitcoincore_rpc::{
    bitcoin::{Network, PrivateKey},
    Auth,
};
use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
pub struct BitcoinOpts {
    #[clap(long, env = "BITCOIN_RPC_URL")]
    pub bitcoin_rpc_url: Option<String>,

    #[clap(long, env = "BITCOIN_RPC_USER")]
    pub bitcoin_rpc_user: Option<String>,

    #[clap(long, env = "BITCOIN_RPC_PASS")]
    pub bitcoin_rpc_pass: Option<String>,

    /// Timeout in milliseconds to wait for connection to bitcoin-core.
    #[clap(long, default_value = "60000")]
    pub bitcoin_connection_timeout_ms: u64,

    /// Url of the electrs server. If unset, a default fallback
    /// is used depending on the detected network.
    #[clap(long)]
    pub electrs_url: Option<String>,

    /// Wif encoded Bitcoin private key
    /// If set, we are to use the light client
    // TODO: load key from file
    #[clap(long, conflicts_with = "bitcoin-rpc-url")]
    pub private_key: Option<PrivateKey>,

    /// Bitcoin network, only needed for
    /// configuring the light client
    #[clap(long, requires = "private-key")]
    pub network: Option<Network>,
}

impl BitcoinOpts {
    fn new_auth(&self) -> Auth {
        Auth::UserPass(
            self.bitcoin_rpc_user.clone().unwrap(),
            self.bitcoin_rpc_pass.clone().unwrap(),
        )
    }

    fn new_client_builder(&self, wallet_name: Option<String>) -> BitcoinCoreBuilder {
        BitcoinCoreBuilder::new(self.bitcoin_rpc_url.clone().unwrap())
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

    pub fn new_light_client(&self) -> BitcoinLight {
        BitcoinLight::new(
            self.electrs_url.clone(),
            self.network.unwrap(),
            self.private_key.unwrap(),
        )
    }
}
