use clap::Parser;
use futures::Future;
use runtime::InterBtcSigner;
use service::{warp, warp::Filter, ConnectionManager, Error, MonitoringConfig, ServiceConfig};
use signal_hook::consts::*;
use signal_hook_tokio::Signals;
use std::net::{Ipv4Addr, SocketAddr};
use tokio_stream::StreamExt;
use vault::{
    metrics::{self, increment_restart_counter},
    VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION,
};

#[derive(Parser, Debug, Clone)]
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

async fn catch_signals<F>(mut shutdown_signals: Signals, future: F) -> Result<(), Error>
where
    F: Future<Output = Result<(), Error>>,
{
    tokio::select! {
        res = future => {
            let _ = res?;
        },
        signal_option = shutdown_signals.next() => {
            if let Some(signal) = signal_option {
                tracing::info!("Received termination signal: {}", signal);
            }
            tracing::info!("Shutting down...");
        }
    }
    Ok(())
}

async fn start() -> Result<(), Error> {
    let opts: Opts = Opts::parse();
    opts.service.logging_format.init_subscriber();

    let (pair, wallet_name) = opts.account_info.get_key_pair()?;
    let signer = InterBtcSigner::new(pair);

    let vault_connection_manager = ConnectionManager::<_, VaultService, _>::new(
        signer.clone(),
        Some(wallet_name.to_string()),
        opts.bitcoin,
        opts.parachain,
        opts.service,
        opts.monitoring.clone(),
        opts.vault,
        increment_restart_counter,
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
        let prometheus_port = opts.monitoring.prometheus_port;

        tokio::task::spawn(async move {
            warp::serve(metrics_route)
                .run(SocketAddr::new(prometheus_host.into(), prometheus_port))
                .await;
        });
    }
    vault_connection_manager.start().await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = catch_signals(
        Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT]).expect("Failed to set up signal listener."),
        start(),
    )
    .await
    {
        tracing::error!("Exiting: {}", err);
        1
    } else {
        0
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

    #[tokio::test]
    async fn test_vault_termination_signal() {
        let termination_signals = &[SIGHUP, SIGTERM, SIGINT, SIGQUIT];
        for sig in termination_signals {
            let task = tokio::spawn(catch_signals(Signals::new(termination_signals).unwrap(), async {
                tokio::time::sleep(Duration::from_millis(100_000)).await;
                Ok(())
            }));
            // Wait for the signals iterator to be polled
            // This `sleep` is based on the test case in `signal-hook-tokio` itself:
            // https://github.com/vorner/signal-hook/blob/a9e5ca5e46c9c8e6de89ff1b3ce63c5ff89cd708/signal-hook-tokio/tests/tests.rs#L50
            thread::sleep(Duration::from_millis(100));
            signal_hook::low_level::raise(*sig).unwrap();
            task.await.unwrap().unwrap();
        }
    }
}
