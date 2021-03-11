use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use log::*;
use runtime::substrate_subxt::PairSigner;
use runtime::{PolkaBtcProvider, PolkaBtcRuntime};
use std::sync::Arc;
use std::time::Duration;
use vault::{Error, Opts};

async fn start() -> Result<(), Error> {
    env_logger::init_from_env(env_logger::Env::default().filter_or(
        env_logger::DEFAULT_FILTER_ENV,
        log::LevelFilter::Info.as_str(),
    ));
    let opts: Opts = Opts::parse();
    let intact_opts = opts.clone();

    info!("Command line arguments: {:?}", opts.clone());

    let (pair, wallet) = opts.account_info.get_key_pair()?;

    let btc_rpc = BitcoinCore::new_with_retry(
        Arc::new(opts.bitcoin.new_client(Some(&wallet))?),
        opts.network.0,
        Duration::from_millis(opts.connection_timeout_ms),
    )
    .await?;

    // load wallet. Exit on failure, since without wallet we can't do a lot
    btc_rpc
        .create_wallet(&wallet)
        .await
        .map_err(|e| Error::WalletInitializationFailure(e))?;

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(pair);
    // only open connection to parachain after bitcoind sync to prevent timeout
    let provider = Arc::new(
        PolkaBtcProvider::from_url_with_retry(
            opts.polka_btc_url,
            Arc::new(signer.into()),
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?,
    );

    vault::start(intact_opts, provider, btc_rpc).await
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
