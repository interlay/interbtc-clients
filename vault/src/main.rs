use clap::Clap;
use runtime::{substrate_subxt::PairSigner, InterBtcRuntime};
use service::{ConnectionManager, ServiceConfig};

use vault::{Error, VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION};

#[derive(Clap, Debug, Clone)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
pub struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    pub account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC Parachain.
    #[clap(flatten)]
    pub parachain: runtime::cli::ConnectionOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    pub bitcoin: bitcoin::cli::BitcoinOpts,

    /// Settings specific to the vault client.
    #[clap(flatten)]
    pub vault: VaultServiceConfig,

    /// General service settings.
    #[clap(flatten)]
    pub service: ServiceConfig,
}

async fn start() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.service.logging_format.init_subscriber();

    let (pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<InterBtcRuntime, _>::new(pair);

    ConnectionManager::<_, VaultService>::new(
        signer.clone(),
        Some(wallet_name.to_string()),
        opts.bitcoin,
        opts.parachain,
        opts.service,
        opts.vault,
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
