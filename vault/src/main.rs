use bitcoin::{Network, PrivateKey};
use clap::Parser;
use futures::Future;
use runtime::{InterBtcSigner, KeyPair, Ss58Codec, DEFAULT_SPEC_NAME, SS58_PREFIX};
use secp256k1::{rand::thread_rng, SecretKey};
use service::{warp, warp::Filter, ConnectionManager, Error, MonitoringConfig, ServiceConfig};
use signal_hook::consts::*;
use signal_hook_tokio::Signals;
use sp_core::crypto::Pair;
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use sysinfo::{System, SystemExt};
use tokio_stream::StreamExt;
use vault::{
    metrics::{self, increment_restart_counter},
    process::PidFile,
    VaultService, VaultServiceConfig, ABOUT, AUTHORS, NAME, VERSION,
};

#[derive(Parser)]
#[clap(args_conflicts_with_subcommands = true)]
struct Cli {
    #[clap(subcommand)]
    sub: Option<Commands>,

    #[clap(flatten)]
    opts: RunVaultOpts,
}

#[derive(Parser)]
enum Commands {
    /// Generate the WIF encoded Bitcoin private key.
    GenerateBitcoinKey(GenerateBitcoinKeyOpts),
    /// Generate the sr25519 parachain key pair.
    GenerateParachainKey(GenerateParachainKeyOpts),
    /// Run the Vault client (default).
    #[clap(name = "run")]
    RunVault(RunVaultOpts),
}

// write the file to stdout or disk - fail if it already exists
fn try_write_file<D: AsRef<[u8]>>(output: &Option<PathBuf>, data: D) -> Result<(), Error> {
    let data = data.as_ref();
    if let Some(output) = output {
        if output.exists() {
            Err(Error::FileAlreadyExists)
        } else {
            std::fs::write(output, data)?;
            Ok(())
        }
    } else {
        std::io::stdout().write_all(data)?;
        Ok(())
    }
}

#[derive(Debug, Parser, Clone)]
struct GenerateBitcoinKeyOpts {
    /// Output file name or stdout if unspecified.
    #[clap(long, value_parser)]
    output: Option<PathBuf>,

    #[clap(long)]
    network: Network,
}

impl GenerateBitcoinKeyOpts {
    fn generate_and_write(&self) -> Result<(), Error> {
        let secret_key = SecretKey::new(&mut thread_rng());
        let private_key = PrivateKey::new(secret_key, self.network);
        let wif = private_key.to_wif();
        let data = wif.as_bytes();

        try_write_file(&self.output, data)
    }
}

#[derive(Debug, Parser, Clone)]
struct GenerateParachainKeyOpts {
    /// Output file name or stdout if unspecified.
    #[clap(long, value_parser)]
    output: Option<PathBuf>,
}

impl GenerateParachainKeyOpts {
    fn generate_and_write(&self) -> Result<(), Error> {
        let (pair, phrase, _) = KeyPair::generate_with_phrase(None);

        let mut keys = serde_json::Map::new();
        keys.insert(
            pair.public().to_ss58check_with_version(SS58_PREFIX.into()),
            serde_json::Value::String(phrase),
        );
        let data = serde_json::to_vec(&keys)?;

        try_write_file(&self.output, data)
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(name = NAME, version = VERSION, author = AUTHORS, about = ABOUT)]
pub struct RunVaultOpts {
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
    F: Future<Output = Result<(), Error>> + Send + 'static,
{
    let blocking_task = tokio::task::spawn(future);
    tokio::select! {
        res = blocking_task => {
            return res?;
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
    let cli: Cli = Cli::parse();
    let opts = cli.opts;
    opts.service.logging_format.init_subscriber();

    match cli.sub {
        Some(Commands::GenerateBitcoinKey(opts)) => {
            return opts.generate_and_write();
        }
        Some(Commands::GenerateParachainKey(opts)) => {
            return opts.generate_and_write();
        }
        _ => (),
    }

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

    // The system information struct should only be created once.
    // Source: https://docs.rs/sysinfo/0.26.1/sysinfo/#usage
    let mut sys = System::new_all();

    // Create a PID file to signal to other processes that a vault is running.
    // This file is auto-removed when `drop`ped.
    let _pidfile = PidFile::create(&String::from(DEFAULT_SPEC_NAME), signer.account_id(), &mut sys)?;

    // Unless termination signals are caught, the PID file is not dropped.
    let main_task = async move { vault_connection_manager.start().await };
    catch_signals(
        Signals::new(&[SIGHUP, SIGTERM, SIGINT, SIGQUIT]).expect("Failed to set up signal listener."),
        main_task,
    )
    .await
}

#[tokio::main]
async fn main() {
    let exit_code = if let Err(err) = start().await {
        tracing::error!("Exiting: {}", err);
        1
    } else {
        0
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use runtime::AccountId;

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

    #[tokio::test]
    async fn test_vault_pid_file() {
        let dummy_account_id = AccountId::new(Default::default());
        let dummy_spec_name = "kintsugi-testnet".to_string();
        let termination_signals = &[SIGHUP, SIGTERM, SIGINT, SIGQUIT];
        let mut sys = System::new_all();

        let task = tokio::spawn({
            let _pidfile = PidFile::create(&dummy_spec_name, &dummy_account_id, &mut sys).unwrap();
            catch_signals(Signals::new(termination_signals).unwrap(), async {
                tokio::time::sleep(Duration::from_millis(100_000)).await;
                Ok(())
            })
        });
        // Wait for the signals iterator to be polled
        // This `sleep` is based on the test case in `signal-hook-tokio` itself:
        // https://github.com/vorner/signal-hook/blob/a9e5ca5e46c9c8e6de89ff1b3ce63c5ff89cd708/signal-hook-tokio/tests/tests.rs#L50
        thread::sleep(Duration::from_millis(1000));
        signal_hook::low_level::raise(SIGINT).unwrap();
        task.await.unwrap().unwrap();

        // the pidfile must have been dropped after the signal was received
        assert_eq!(
            PidFile::compute_path(&dummy_spec_name, &dummy_account_id).exists(),
            false
        );
    }
}
