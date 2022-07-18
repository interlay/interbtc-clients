mod error;
mod vaultvisor;

use clap::Parser;
use vaultvisor::{get_release, ws_client};

use std::{
    fmt::Debug,
    fs,
    path::Path,
    process::{Command, Stdio},
    str,
};

use error::Error;

use crate::vaultvisor::{does_vault_binary_exist, run_vault_binary};

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
    let release = get_release(&rpc_client).await?;

    if !does_vault_binary_exist(&release)? {
        Command::new("wget")
            .arg(release.uri.clone())
            .stdout(Stdio::inherit())
            .spawn()?
            .wait_with_output()?;
        // TODO: Move the binary to a user-specified path?
        log::info!(
            "Downloaded vault release v{} from {}",
            release.semver_version,
            release.uri
        );
        Command::new("chmod")
            .arg("+x")
            .arg(release.binary_name.clone())
            .stdout(Stdio::inherit())
            .spawn()?
            .wait_with_output()?;
    } else {
        log::info!("Vault binary already exists, skipping download.")
    }

    loop {
        match run_vault_binary(&release.binary_name, vault_args.clone()).await {
            Err(e) => log::error!("Vault binary crashed: {:?}", e),
            Ok(_) => log::error!("Vault binary finished execution unexpectedly."),
        }
        log::info!("Restarting vault...");
    }
}
