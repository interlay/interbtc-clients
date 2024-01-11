#![cfg(feature = "cli")]

use crate::{BitcoinCoreApi, BitcoinCoreBuilder, Error};
use bitcoincore_rpc::{bitcoin::Network, Auth};
use clap::Parser;
use std::{sync::Arc, time::Duration};

#[cfg(feature = "light-client")]
use {
    crate::{error::KeyLoadingError, BitcoinLight, PrivateKey},
    std::path::PathBuf,
};

#[cfg(feature = "light-client")]
fn get_private_key_from_file(file_path: &PathBuf) -> Result<PrivateKey, KeyLoadingError> {
    let data = std::fs::read(file_path)?;
    let wif = String::from_utf8(data)?;
    Ok(PrivateKey::from_wif(wif.trim())?)
}

#[derive(Parser, Debug, Clone, Default)]
pub struct BitcoinOpts {
    #[clap(long, env = "BITCOIN_RPC_URL")]
    #[cfg_attr(feature = "light-client", clap(conflicts_with_all(["light", "bitcoin_wif"])))]
    pub bitcoin_rpc_url: Option<String>,

    #[clap(long, env = "BITCOIN_RPC_USER")]
    #[cfg_attr(feature = "light-client", clap(conflicts_with_all(["light", "bitcoin_wif"])))]
    pub bitcoin_rpc_user: Option<String>,

    #[clap(long, env = "BITCOIN_RPC_PASS")]
    #[cfg_attr(feature = "light-client", clap(conflicts_with_all(["light", "bitcoin_wif"])))]
    pub bitcoin_rpc_pass: Option<String>,

    /// Timeout in milliseconds to wait for connection to bitcoin-core.
    #[clap(long, default_value = "60000")]
    pub bitcoin_connection_timeout_ms: u64,

    /// Url of the electrs server. If unset, a default fallback
    /// is used depending on the detected network.
    #[clap(long)]
    pub electrs_url: Option<String>,

    /// Experimental: Run in light client mode
    #[cfg_attr(feature = "light-client", clap(long, requires_all(["bitcoin_wif"])))]
    #[cfg(feature = "light-client")]
    pub light: bool,

    /// File containing the WIF encoded Bitcoin private key
    #[cfg_attr(feature = "light-client", clap(
        long,
        requires = "light",
        conflicts_with_all(["bitcoin_rpc_url", "bitcoin_rpc_user", "bitcoin_rpc_pass"]),
        value_parser
    ))]
    #[cfg(feature = "light-client")]
    pub bitcoin_wif: Option<PathBuf>,
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

    #[cfg(feature = "light-client")]
    fn new_light_client(&self) -> Result<BitcoinLight, Error> {
        Ok(BitcoinLight::new(
            self.electrs_url.clone(),
            get_private_key_from_file(self.bitcoin_wif.as_ref().expect("Private key not set"))?,
        )?)
    }

    pub async fn new_client(
        &self,
        wallet_name: Option<String>,
    ) -> Result<Arc<dyn BitcoinCoreApi + Send + Sync>, Error> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "light-client")] {
                Ok(if self.light {
                    Arc::new(self.new_light_client()?)
                } else {
                    let bitcoin_core = self
                        .new_client_builder(wallet_name)
                        .build_and_connect(Duration::from_millis(self.bitcoin_connection_timeout_ms))
                        .await?;
                    bitcoin_core.sync().await?;
                    bitcoin_core.create_or_load_wallet().await?;
                    Arc::new(bitcoin_core)
                })
            } else {
                let bitcoin_core = self
                    .new_client_builder(wallet_name)
                    .build_and_connect(Duration::from_millis(self.bitcoin_connection_timeout_ms))
                    .await?;
                bitcoin_core.sync().await?;
                bitcoin_core.create_or_load_wallet().await?;
                Ok(Arc::new(bitcoin_core))
            }
        }
    }

    pub async fn new_walletless(
        &self,
        wallet_name: Option<String>,
    ) -> Result<Arc<dyn BitcoinCoreApi + Send + Sync>, Error> {
        let bitcoin_core = self
            .new_client_builder(wallet_name)
            .build_and_connect(Duration::from_millis(self.bitcoin_connection_timeout_ms))
            .await?;
        bitcoin_core.sync().await?;
        Ok(Arc::new(bitcoin_core))
    }

    pub fn new_client_with_network(
        &self,
        wallet_name: Option<String>,
        network: Network,
    ) -> Result<Arc<dyn BitcoinCoreApi + Send + Sync>, Error> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "light-client")] {
                Ok(if self.light {
                    Arc::new(self.new_light_client()?)
                } else {
                    Arc::new(self.new_client_builder(wallet_name).build_with_network(network)?)
                })
            } else {
                Ok(Arc::new(self.new_client_builder(wallet_name).build_with_network(network)?))
            }
        }
    }
}
