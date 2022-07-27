mod error;
mod vaultvisor;

use clap::Parser;
use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use vaultvisor::ws_client;

use error::Error;
use std::{
    convert::TryInto,
    fmt::Debug,
    fs::{self, File},
    path::Path,
    str,
};

use crate::vaultvisor::{get_release, run_vault_binary, try_download_client_binary, BLOCK_TIME};

#[derive(Parser, Debug, Clone)]
#[clap(version, author, about, trailing_var_arg = true)]
struct Opts {
    #[clap(long)]
    chain_rpc: String,
    vault_args: Vec<String>,
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
    let vault_args = opts.vault_args;
    let rpc_client = ws_client(&opts.chain_rpc).await?;
    log::info!("Vaultvisor connected to the parachain");
    let mut last_current_release = try_download_client_binary(&rpc_client, false)
        .await?
        .expect("No current release");
    // let last_pending_release = try_download_client_binary(&rpc_client, true).await?;

    println!("{:?}", last_current_release);
    let mut vault_process = run_vault_binary(&last_current_release.bin_name, vault_args.clone()).await?;
    loop {
        let current_release = try_download_client_binary(&rpc_client, false)
            .await?
            .expect("No current release");
        if current_release.release.uri != last_current_release.release.uri {
            last_current_release = current_release;
            // Shut down the outdated binary, start the new one
            signal::kill(
                Pid::from_raw(
                    vault_process
                        .id()
                        .try_into()
                        .map_err(|_| Error::IntegerConversionError)?,
                ),
                Signal::SIGINT,
            )?;
            vault_process = run_vault_binary(&last_current_release.bin_name, vault_args.clone()).await?;
        }
        tokio::time::sleep(BLOCK_TIME).await;
    }
}
