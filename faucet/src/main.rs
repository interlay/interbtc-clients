mod error;
mod http;
mod system;

use clap::Clap;
use error::Error;
use git_version::git_version;
use runtime::{substrate_subxt::PairSigner, PolkaBtcRuntime};
use service::{ConnectionManager, RestartPolicy};
use system::{FaucetService, FaucetServiceConfig};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC-Parachain.
    #[clap(flatten)]
    parachain: runtime::cli::ConnectionOpts,

    /// Settings specific to the faucet client.
    #[clap(flatten)]
    faucet: FaucetServiceConfig,

    /// What to do if the connection to the btc-parachain drops.
    #[clap(long, default_value = "always")]
    restart_policy: RestartPolicy,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, log::LevelFilter::Info.as_str()),
    );
    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);

    ConnectionManager::<(), _, FaucetService>::new(signer.clone(), opts.parachain, opts.faucet, opts.restart_policy)
        .start()
        .await?;

    Ok(())
}
