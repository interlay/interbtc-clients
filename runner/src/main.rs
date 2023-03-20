mod error;
mod runner;

use clap::Parser;

use error::Error;

use runner::ClientType;
use signal_hook::consts::*;
use signal_hook_tokio::Signals;
use std::{fmt::Debug, path::PathBuf};

use crate::runner::Runner;

#[derive(Parser, Debug, Clone)]
#[clap(version, author, about, trailing_var_arg = true)]
pub struct Opts {
    /// Client to run, one of: vault, oracle, faucet. Default is `vault`.
    #[clap(long, default_value = "vault")]
    pub client_type: ClientType,

    /// Parachain websocket URL.
    #[clap(long)]
    pub parachain_ws: String,

    /// Download path for the client executable.
    #[clap(long, default_value = ".")]
    pub download_path: PathBuf,

    /// CLI arguments to pass to the client executable.
    pub client_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let runner = Runner::new(opts);
    let shutdown_signals = Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    Runner::run(Box::new(runner), shutdown_signals).await?;
    Ok(())
}
