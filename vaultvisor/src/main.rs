mod error;
mod vaultvisor;

use clap::Parser;

use error::Error;

use bytes::Bytes;
use codec::{Decode, Encode};
use jsonrpsee::core::client::Client as WsClient;
use sp_core::Bytes as SpCoreBytes;

use std::{fmt::Debug, path::PathBuf, str};

use async_trait::async_trait;

use crate::vaultvisor::{run, Vaultvisor, VaultvisorUtils};

#[derive(Parser, Debug, Clone)]
#[clap(version, author, about, trailing_var_arg = true)]
struct Opts {
    #[clap(long)]
    chain_rpc: String,
    #[clap(long, default_value = ".")]
    download_path: PathBuf,
    vault_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();
    let rpc_client = Vaultvisor::ws_client(&opts.chain_rpc).await?;
    log::info!("Connected to the parachain");

    let mut vaultvisor = Vaultvisor::new(rpc_client, opts.vault_args, opts.download_path);
    run(&mut vaultvisor).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sp_core::H256;
    use std::{path::PathBuf, process::Child, str::FromStr};

    use crate::{
        vaultvisor::{run, ClientRelease, DownloadedRelease},
        *,
    };

    mockall::mock! {
        Vaultvisor {}

        #[async_trait]
        pub trait VaultvisorUtils {
            fn parachain_rpc(&self) -> &WsClient;
            fn vault_args(&self) -> &Vec<String>;
            fn child_proc(&self) -> &Option<Child>;
            fn downloaded_release(&self) -> &Option<DownloadedRelease>;
            fn download_path(&self) -> &PathBuf;
            async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error>;
            async fn download_binary(&mut self, release: ClientRelease) -> Result<(), Error>;
            fn uri_to_bin_path(&self, uri: &String) -> Result<(String, PathBuf), Error>;
            fn delete_downloaded_release(&mut self) -> Result<(), Error>;
            async fn run_binary(&mut self) -> Result<(), Error>;
            fn terminate_proc_and_wait(&mut self) -> Result<(), Error>;
            async fn get_request_bytes(url: String) -> Result<Bytes, Error>;
            async fn ws_client(url: &str) -> Result<WsClient, Error>;
        }
    }

    // #[tokio::test]
    // async fn test_vaultvisor() {
    //     let mut vaultvisor = MockVaultvisor::default();
    //     vault.
    //     v
    // }

    #[tokio::test]
    async fn test_vaultvisor() {
        let mut vaultvisor = MockVaultvisor::default();
        let mock_download_path = PathBuf::from_str(".").unwrap();
        let mock_release_uri =
            "https://github.com/interlay/interbtc-clients/releases/download/1.15.0/vault-standalone-metadata";
        let mock_client_release = |_| {
            Ok(Some(ClientRelease {
                uri: "https://github.com/interlay/interbtc-clients/releases/download/1.15.0/vault-standalone-metadata"
                    .to_string(),
                code_hash: H256::default(),
            }))
        };
        let mock_downloaded_release = Some(DownloadedRelease {
            release: mock_client_release(false).unwrap().unwrap(),
            path: mock_download_path.clone(),
            bin_name: "vault-standalone-metadata".to_string(),
        });
        vaultvisor.expect_download_path().return_const(mock_download_path);
        vaultvisor.expect_try_get_release().returning(mock_client_release);
        vaultvisor.expect_download_binary().returning(|_| Ok(()));
        vaultvisor.expect_run_binary().returning(|| Ok(()));
        vaultvisor
            .expect_downloaded_release()
            .return_const(mock_downloaded_release);
        run(&mut vaultvisor).await.unwrap();
    }
}
