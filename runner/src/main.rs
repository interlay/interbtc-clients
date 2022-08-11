mod error;
mod runner;

use clap::Parser;

use error::Error;

use futures::TryFutureExt;
use futures_util::FutureExt;
use signal_hook::consts::*;
use signal_hook_tokio::Signals;
use std::{fmt::Debug, path::PathBuf};

use crate::runner::{retry_with_log_async, ws_client, Runner};

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
    let rpc_client = retry_with_log_async(
        || ws_client(&opts.parachain_ws).into_future().boxed(),
        "Error fetching executable".to_string(),
    )
    .await?;
    log::info!("Connected to the parachain");

    let runner = Runner::new(rpc_client, opts.vault_args, opts.download_path);
    let shutdown_signals = Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    Runner::run(Box::new(runner), shutdown_signals).await?;
    Ok(())
}
