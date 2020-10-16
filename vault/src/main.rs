mod error;

use bitcoin::BitcoinCore;
use clap::Clap;
use error::Error;
use log::{error, info};
use runtime::substrate_subxt::PairSigner;
use runtime::{H256Le, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet};
use sp_keyring::AccountKeyring;
use std::sync::Arc;

/// The Vault client intermediates between Bitcoin Core
/// and the PolkaBTC Parachain.
#[derive(Clap)]
#[clap(version = "0.1", author = "Interlay <contact@interlay.io>")]
struct Opts {
    /// Parachain URL, can be over WebSockets or HTTP.
    #[clap(long, default_value = "ws://127.0.0.1:9944")]
    polka_btc_url: String,

    /// Keyring for vault.
    #[clap(long, default_value = "bob")]
    keyring: AccountKeyring,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();

    let btc_rpc = Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));

    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = &Arc::new(provider.clone());

    provider
        .on_request_redeem(
            |event| async move {
                info!("New redeem request: {}", event.redeem_id);
                // TODO: check account is owned

                // let txid = btc.send_to_address(btc_address, event.amount_polka_btc).await?;
                // let proof = btc.get_proof_for(txid)?;
                // let raw_tx = btc.get_raw_tx_for(txid)?;

                // TODO: get block height and convert txid
                arc_provider
                    .execute_redeem(event.redeem_id, H256Le::zero(), 0, vec![], vec![])
                    .await
                    .unwrap();
            },
            |error| error!("Error reading redeem event: {}", error.to_string()),
        )
        .await?;

    Ok(())
}
