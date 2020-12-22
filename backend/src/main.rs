mod error;
mod http;

use bitcoin::BitcoinCoreApi;
use clap::Clap;
use error::Error;
use log::info;
use std::convert::TryInto;
use std::time::Duration;

/// Indexing service to write and read `OP_RETURN` data.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Starting height to scan block headers for transactions
    /// containing `OP_RETURN` outputs.
    #[clap(long)]
    start_height: Option<u32>,

    /// Delay for checking for new Bitcoin blocks (in seconds).
    #[clap(long, default_value = "60")]
    block_delay: u64,

    /// Connection settings for Bitcoin Core.
    #[clap(flatten)]
    bitcoin: bitcoin::cli::BitcoinOpts,
}

async fn scan(
    btc_rpc: bitcoin::BitcoinCore,
    btc_height: u32,
    block_delay: Duration,
) -> Result<(), Error> {
    let mut btc_height = btc_height;
    loop {
        info!("Scanning height {}", btc_height);
        // TODO: handle errors here, we probably want to retry
        let block_hash = btc_rpc.wait_for_block(btc_height, block_delay).await?;
        for maybe_tx in btc_rpc.get_block_transactions(&block_hash)? {
            if let Some(_tx) = maybe_tx {
                // let _results = bitcoin::extract_op_returns(tx);
                // TODO: store key-value (op_return:tx_id) in db
                // e.g. https://github.com/rust-rocksdb/rust-rocksdb
            }
        }
        btc_height += 1;
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let btc_client = opts.bitcoin.new_client(None)?;
    let btc_rpc = bitcoin::BitcoinCore::new(btc_client, bitcoin::Network::Regtest);

    let btc_height = if let Some(height) = opts.start_height {
        height
    } else {
        // get the latest height if `None` given
        btc_rpc.get_block_count()?.try_into()?
    };

    let block_delay = Duration::from_secs(opts.block_delay);

    // run indexer and web service concurrently
    let result = tokio::try_join!(scan(btc_rpc, btc_height, block_delay), http::start());
    match result {
        Ok((_, _)) => Ok(()),
        Err(err) => Err(err),
    }
}
