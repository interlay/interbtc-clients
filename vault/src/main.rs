use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use log::*;
use runtime::substrate_subxt::PairSigner;
use runtime::{PolkaBtcProvider, PolkaBtcRuntime};
use std::sync::Arc;
use std::time::Duration;
use vault::{start, Error, Opts};

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let intact_opts = opts.clone();

    info!("Command line arguments: {:?}", opts.clone());

    let (pair, wallet) = opts.account_info.get_key_pair()?;

    let btc_rpc = Arc::new(BitcoinCore::new(
        opts.bitcoin.new_client(Some(&wallet))?,
        opts.network.0,
    ));

    info!("Waiting for bitcoin core to sync");
    btc_rpc
        .wait_for_block_sync(Duration::from_millis(opts.bitcoin_timeout_ms))
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
            signer,
            Duration::from_millis(opts.connection_timeout_ms),
        )
        .await?,
    );

    start(intact_opts, provider, btc_rpc).await
}
