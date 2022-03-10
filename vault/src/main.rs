use clap::Clap;
use runtime::InterBtcSigner;
use service::{warp, warp::Filter, ConnectionManager, Error, MonitoringConfig, ServiceConfig};
use std::net::{Ipv4Addr, SocketAddr};

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

    /// Prometheus monitoring settings.
    #[clap(flatten)]
    pub monitoring: MonitoringConfig,
}

async fn start() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.service.logging_format.init_subscriber();

    let (pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(pair);

    let vault_connection_manager = ConnectionManager::<_, VaultService>::new(
        signer.clone(),
        Some(wallet_name.to_string()),
        opts.bitcoin,
        opts.parachain,
        opts.service,
        opts.monitoring.clone(),
        opts.vault,
    );

    if !opts.monitoring.no_prometheus {
        metrics::register_custom_metrics()?;
        let metrics_route = warp::path("metrics").and_then(metrics::metrics_handler);
        let prometheus_host = if opts.monitoring.prometheus_external {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        };
        tracing::info!(
            "Starting Prometheus exporter at http://{}:{}",
            prometheus_host,
            opts.monitoring.prometheus_port
        );
        let (_, future_result) = futures::join!(
            warp::serve(metrics_route).run(SocketAddr::new(prometheus_host.into(), opts.monitoring.prometheus_port,)),
            tokio::task::spawn(async move { vault_connection_manager.start().await }),
        );
        future_result?
    } else {
        vault_connection_manager.start().await?;
        Ok(())
    }
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
