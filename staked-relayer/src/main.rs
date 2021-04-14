use staked_relayer::{system::*, Error};

use clap::Clap;
use git_version::git_version;
use runtime::{substrate_subxt::PairSigner, PolkaBtcRuntime};
use service::{ConnectionManager, RestartPolicy};

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

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    /// Settings specific to the relayer client.
    #[clap(flatten)]
    relayer: RelayerServiceConfig,

    /// What to do if the connection to the btc-parachain drops.
    #[clap(long, default_value = "always")]
    restart_policy: RestartPolicy,
}

async fn start() -> Result<(), Error> {
    staked_relayer::init_subscriber();

    let opts: Opts = Opts::parse();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(key_pair);

    let bitcoin_core = opts.bitcoin.new_client(None)?;

    ConnectionManager::<_, _, RelayerService>::new(
        signer.clone(),
        bitcoin_core,
        opts.parachain,
        opts.relayer,
        opts.restart_policy,
    )
    .start()
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = start().await {
        eprintln!("Error: {}", err);
        1
    } else {
        0
    };
    std::process::exit(exit_code);
}
