#![cfg(feature = "cli")]

use crate::{error::KeyLoadingError, BitcoinCoreApi, BitcoinCoreBuilder, BitcoinLight, Error};
use bitcoincore_rpc::{
    bitcoin::{Network, PrivateKey},
    Auth,
};
use clap::Parser;
use std::{path::PathBuf, sync::Arc, time::Duration};

fn get_wif_from_file(file_path: &PathBuf) -> Result<PrivateKey, KeyLoadingError> {
    let data = std::fs::read(file_path)?;
    let wif = String::from_utf8(data)?;
    Ok(PrivateKey::from_wif(wif.trim())?)
}

#[derive(Parser, Debug, Clone, Default)]
pub struct BitcoinOpts {
    #[clap(
        long,
        conflicts_with_all(&["light", "bitcoin-wif", "network"]),
        env = "BITCOIN_RPC_URL"
    )]
    pub bitcoin_rpc_url: Option<String>,

    #[clap(
        long,
        conflicts_with_all(&["light", "bitcoin-wif", "network"]),
        env = "BITCOIN_RPC_USER"
    )]
    pub bitcoin_rpc_user: Option<String>,

    #[clap(
        long,
        conflicts_with_all(&["light", "bitcoin-wif", "network"]),
        env = "BITCOIN_RPC_PASS"
    )]
    pub bitcoin_rpc_pass: Option<String>,

    /// Timeout in milliseconds to wait for connection to bitcoin-core.
    #[clap(long, default_value = "60000")]
    pub bitcoin_connection_timeout_ms: u64,

    /// Url of the electrs server. If unset, a default fallback
    /// is used depending on the detected network.
    #[clap(long)]
    pub electrs_url: Option<String>,

    /// Experimental: Run in light client mode
    #[clap(long, requires_all(&["bitcoin-wif", "network"]))]
    pub light: bool,

    /// File containing the WIF encoded Bitcoin private key
    #[clap(
        long,
        requires = "light",
        conflicts_with_all(&["bitcoin-rpc-url", "bitcoin-rpc-user", "bitcoin-rpc-pass"]),
        parse(from_os_str)
    )]
    pub bitcoin_wif: Option<PathBuf>,

    /// Bitcoin network, only needed for
    /// configuring the light client
    #[clap(
        long,
        requires = "light",
        conflicts_with_all(&["bitcoin-rpc-url", "bitcoin-rpc-user", "bitcoin-rpc-pass"]),
    )]
    pub network: Option<Network>,
}

impl BitcoinOpts {
    fn new_auth(&self) -> Auth {
        Auth::UserPass(
            self.bitcoin_rpc_user.clone().expect("User not set"),
            self.bitcoin_rpc_pass.clone().expect("Pass not set"),
        )
    }

    pub fn new_client_builder(&self, wallet_name: Option<String>) -> BitcoinCoreBuilder {
        BitcoinCoreBuilder::new(self.bitcoin_rpc_url.clone().expect("Url not set"))
            .set_auth(self.new_auth())
            .set_wallet_name(wallet_name)
            .set_electrs_url(self.electrs_url.clone())
    }

    pub async fn new_client(
        &self,
        wallet_name: Option<String>,
    ) -> Result<Arc<dyn BitcoinCoreApi + Send + Sync>, Error> {
        Ok(if self.light {
            Arc::new(BitcoinLight::new(
                self.electrs_url.clone(),
                self.network.expect("Network not set"),
                get_wif_from_file(self.bitcoin_wif.as_ref().expect("Private key not set"))?,
            )?)
        } else {
            let bitcoin_core = self
                .new_client_builder(wallet_name)
                .build_and_connect(Duration::from_millis(self.bitcoin_connection_timeout_ms))
                .await?;
            bitcoin_core.sync().await?;
            bitcoin_core.create_or_load_wallet().await?;
            Arc::new(bitcoin_core)
        })
    }

    pub fn new_client_with_network(
        &self,
        wallet_name: Option<String>,
        network: Network,
    ) -> Result<Arc<dyn BitcoinCoreApi + Send + Sync>, Error> {
        Ok(if self.light {
            Arc::new(BitcoinLight::new(
                self.electrs_url.clone(),
                network,
                get_wif_from_file(self.bitcoin_wif.as_ref().expect("Private key not set"))?,
            )?)
        } else {
            Arc::new(self.new_client_builder(wallet_name).build_with_network(network)?)
        })
    }
}
