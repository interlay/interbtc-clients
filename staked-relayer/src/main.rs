use clap::Clap;
use runtime::{substrate_subxt::PairSigner, InterBtcRuntime};
use service::{ConnectionManager, ServiceConfig};

use staked_relayer::{system::*, Error};

#[derive(Clap)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
struct Opts {
    /// Keyring / keyfile options.
    #[clap(flatten)]
    account_info: runtime::cli::ProviderUserOpts,

    /// Connection settings for the BTC Parachain.
    #[clap(flatten)]
    parachain: runtime::cli::ConnectionOpts,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,

    /// Settings specific to the relayer client.
    #[clap(flatten)]
    relayer: RelayerServiceConfig,

    /// General service settings.
    #[clap(flatten)]
    service: ServiceConfig,
}

async fn start() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.service.logging_format.init_subscriber();

    let (key_pair, _) = opts.account_info.get_key_pair()?;
    let signer = PairSigner::<InterBtcRuntime, _>::new(key_pair);

    ConnectionManager::<_, RelayerService>::new(
        signer.clone(),
        None,
        opts.bitcoin,
        opts.parachain,
        opts.service,
        opts.relayer,
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
