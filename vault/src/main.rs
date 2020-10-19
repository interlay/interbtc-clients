mod error;

use backoff::{future::FutureOperation as _, ExponentialBackoff};
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use error::Error;
use log::{error, info};
use runtime::{
    H256Le, PolkaBtcProvider, PolkaBtcRequestRedeemEvent, PolkaBtcRuntime, RedeemPallet,
};
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::PairSigner;

// keep trying for 24 hours
const MAX_RETRYING_TIME: Duration = Duration::from_secs(24 * 60 * 60);

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
    let btc_rpc = &Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = &Arc::new(provider.clone());

    let vault_id = &opts.keyring.to_account_id();

    // log vault registration result, but keep going upon error, since it might just be
    // that this vault already registered. Note that we can't match this specific error
    // due to inner error type path being private
    match arc_provider
        .register_vault(
            5_000_000_000_000,
            bitcoin::get_hash_from_string("bcrt1qywc4rq6sd778a0zud325xlk5yzmd2w3ed9larg")
                .map_err(|x| -> bitcoin::Error { x.into() })?,
        )
        .await
    {
        Ok(_) => info!("registered vault ok"),
        Err(e) => error!("Failed to register vault {:?} --- {}", e, e.to_string()),
    };

    provider
        .on_request_redeem(
            |event| async move {
                if event.vault_id != vault_id.clone() {
                    return;
                }
                info!("Received redeem request #{}", event.redeem_id);
                match handle_redeem_request(&event, btc_rpc, arc_provider).await {
                    Ok(_) => info!("Completed redeem request #{}", event.redeem_id),
                    Err(e) => error!(
                        "Failed to process redeem request #{}: {}",
                        event.redeem_id,
                        e.to_string()
                    ),
                }
            },
            |error| error!("Error reading redeem event: {}", error.to_string()),
        )
        .await?;

    Ok(())
}

async fn handle_redeem_request(
    event: &PolkaBtcRequestRedeemEvent,
    btc_rpc: &Arc<BitcoinCore>,
    arc_provider: &Arc<PolkaBtcProvider>,
) -> Result<(), Error> {
    let address = bitcoin::hash_to_p2wpkh(event.btc_address, bitcoin::Network::Regtest)
        .map_err(|e| -> bitcoin::Error { e.into() })?;

    // Step 1: make bitcoin transfer. Note: do not retry this call;
    // the call could fail to get the metadata even if the transaction
    // itself was successful
    let tx_metadata = btc_rpc
        .send_to_address(
            address.clone(),
            event.amount_polka_btc as u64,
            &event.redeem_id.to_fixed_bytes(),
            MAX_RETRYING_TIME,
        )
        .await?;

    // step 2: execute redeem to get the dots
    (|| async {
        Ok(arc_provider
            .execute_redeem(
                event.redeem_id,
                H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
                tx_metadata.block_height,
                tx_metadata.proof.clone(),
                tx_metadata.raw_tx.clone(),
            )
            .await?)
    })
    .retry(get_retry_policy())
    .await?;

    Ok(())
}

// async fn retry(f: F) -> T
// where F:Fn() -> T {
//     (|| async {
//         f();
//     })
//     .retry(get_retry_policy())
//     .await?
// }

fn get_retry_policy() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(MAX_RETRYING_TIME),
        ..Default::default()
    }
}
