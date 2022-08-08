mod error;
mod runner;

use clap::Parser;

use error::Error;

use std::{fmt::Debug, path::PathBuf};

use crate::runner::{ws_client, Runner};

#[derive(Parser, Debug, Clone)]
#[clap(version, author, about, trailing_var_arg = true)]
struct Opts {
    /// Parachain websocket URL.
    #[clap(long)]
    parachain_ws: String,

    /// Download path for the vault executable.
    #[clap(long, default_value = ".")]
    download_path: PathBuf,

    /// CLI arguments to pass to the vault executable.
    vault_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();
    let rpc_client = ws_client(&opts.parachain_ws).await?;
    log::info!("Connected to the parachain");

    let mut runner = Runner::new(rpc_client, opts.vault_args, opts.download_path);
    runner.run().await?;
    Ok(())
}
