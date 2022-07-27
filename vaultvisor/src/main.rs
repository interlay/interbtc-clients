mod error;
mod vaultvisor;

use clap::Parser;
use vaultvisor::{get_release_uri, ws_client};

use error::Error;
use std::{
    fmt::Debug,
    fs::{self, File},
    path::Path,
    str,
};

use crate::vaultvisor::{run_vault_binary, try_download_client_binary};

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
struct Opts {
    #[clap(long)]
    chain_rpc: String,

    #[clap(long)]
    vault_config_file: String,
}

fn get_args_from_file(file: &str) -> Vec<String> {
    let args_string = fs::read_to_string(Path::new(file))
        .expect("Something went wrong reading the vault config file.")
        // Remove newlines and escape characters
        .replace(&['\n', '\\'][..], " ");

    // split entries to match the format of `Command::args`
    args_string
        .split(' ')
        .filter(|arg| !arg.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();
    let vault_args = get_args_from_file(&opts.vault_config_file);
    let rpc_client = ws_client(&opts.chain_rpc).await?;
    log::info!("Vaultvisor connected to the parachain",);
    let release_uri = get_release_uri(&rpc_client).await?;

    let binary_name = try_download_client_binary(release_uri).await?;

    loop {
        match run_vault_binary(&binary_name, vault_args.clone()).await {
            Err(e) => log::error!("Vault binary crashed: {:?}", e),
            Ok(_) => log::error!("Vault binary finished execution unexpectedly."),
        }
        log::info!("Restarting vault...");
    }
}
