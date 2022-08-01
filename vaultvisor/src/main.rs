mod error;
mod vaultvisor;

use clap::Parser;

use error::Error;

use std::{fmt::Debug, path::PathBuf};

use crate::vaultvisor::{run, ws_client, Vaultvisor};

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
    println!("{:?}", opts.vault_args);
    let rpc_client = ws_client(&opts.chain_rpc).await?;
    log::info!("Connected to the parachain");

    let mut vaultvisor = Vaultvisor::new(rpc_client, opts.vault_args, opts.download_path);
    run(&mut vaultvisor).await?;
    Ok(())
}
