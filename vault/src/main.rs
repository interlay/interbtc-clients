use clap::Clap;
use runtime::InterBtcSigner;
use service::{warp, warp::Filter, ConnectionManager, Error, ServiceConfig};

use vault::{metrics, VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION};

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
    let signer = InterBtcSigner::new(pair);

    metrics::register_custom_metrics()?;
    let metrics_route = warp::path("metrics").and_then(metrics::metrics_handler);

    let vault_connection_manager = ConnectionManager::<_, VaultService>::new(
        signer.clone(),
        Some(wallet_name.to_string()),
        opts.bitcoin,
        opts.parachain,
        opts.service,
        opts.vault,
    );

    let (_, future_result) = futures::join!(
        warp::serve(metrics_route).run(([0, 0, 0, 0], 8080)),
        tokio::task::spawn(async move { vault_connection_manager.start().await }),
    );

    future_result?
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
