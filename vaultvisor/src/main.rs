mod error;
mod vaultvisor;

use clap::Parser;

use error::Error;
use std::{
    fmt::Debug,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Child,
    str,
};

use crate::vaultvisor::{Vaultvisor, VaultvisorUtils};

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
    log::info!("Vaultvisor connected to the parachain");

    Vaultvisor::new(rpc_client, opts.vault_args, opts.download_path)
        .run()
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        vaultvisor::{ClientRelease, DownloadedRelease},
        *,
    };
    use mocktopus::{
        macros::*,
        mocking::{MockResult, Mockable},
    };

    mockall::mock! {
        Vaultvisor {}

        #[async_trait]
        pub trait VaultvisorUtils {
            async fn query_storage(&self, maybe_storage_key: Option<&str>, method: &str) -> Option<SpCoreBytes>;
            async fn read_chain_storage<T: Decode + Debug>(&self, maybe_storage_key: Option<&str>) -> Result<Option<T>, Error>;
            async fn try_get_release(&self, pending: bool) -> Result<Option<ClientRelease>, Error>;
            async fn download_binary(&mut self, release: ClientRelease, pending: bool) -> Result<(), Error>;
            fn delete_downloaded_release(&mut self) -> Result<(), Error>;
            async fn run_binary(&mut self) -> Result<(), Error>;
            fn terminate_proc_and_wait(&mut self) -> Result<(), Error>;
            async fn get_request_bytes(url: String) -> Result<Bytes, Error>;
            async fn ws_client(url: &str) -> Result<WsClient, Error>;
        }
    }

    #[tokio::test]
    async fn test_vaultvisor() {
        // let mut btc_rpc = MockVaultvisor::new();
        // btc_rpc
        //     .expect_get_balance()
        //     .returning(move |_| Ok(Amount::from_btc(3.0).unwrap()));
        // let vault_data = VaultData {
        //     vault_id: dummy_vault_id(),
        //     btc_rpc,
        //     metrics: PerCurrencyMetrics::dummy(),
        // };
    }
}
