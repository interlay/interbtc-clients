use clap::Clap;
use git_version::git_version;
use runtime::{substrate_subxt::PairSigner, PolkaBtcRuntime};
use service::{ConnectionManager, RestartPolicy};

use vault::{Error, VaultService, VaultServiceConfig};

const VERSION: &str = git_version!(args = ["--tags"]);
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const NAME: &str = env!("CARGO_PKG_NAME");
const ABOUT: &str = env!("CARGO_PKG_DESCRIPTION");

#[derive(Clap, Debug, Clone)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
pub struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    pub account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC-Parachain.
    #[clap(flatten)]
    pub parachain: runtime::cli::ConnectionOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    pub bitcoin: bitcoin::cli::BitcoinOpts,

    /// Settings specific to the vault client.
    #[clap(flatten)]
    pub vault: VaultServiceConfig,

    /// Restart or stop internal service on error.
    #[clap(long, default_value = "always")]
    pub restart_policy: RestartPolicy,

    /// Logging output format.
    #[clap(long, default_value = "full")]
    logging_format: LoggingFormat,
}

async fn start() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.logging_format.init_subscriber();

    tracing::info!("Command line arguments: {:?}", opts.clone());

    let (pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(pair);

    let bitcoin_core = opts.bitcoin.new_client(Some(wallet_name.to_string()))?;

    ConnectionManager::<_, _, VaultService>::new(
        signer.clone(),
        bitcoin_core,
        opts.parachain,
        opts.vault,
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
