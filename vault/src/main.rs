mod error;

use backoff::{future::FutureOperation as _, ExponentialBackoff};
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use clap::Clap;
use error::Error;
use log::{error, info};
use runtime::{
    pallets::{issue::RequestIssueEvent, redeem::RequestRedeemEvent},
    substrate_subxt::PairSigner,
    H256Le, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet,
};
use sp_core::crypto::AccountId32;
use sp_keyring::AccountKeyring;
use std::sync::Arc;
use std::time::Duration;

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

    #[clap(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    let opts: Opts = Opts::parse();
    let btc_rpc = Arc::new(BitcoinCore::new(bitcoin::bitcoin_rpc_from_env()?));
    let signer = PairSigner::<PolkaBtcRuntime, _>::new(opts.keyring.pair());
    let provider = PolkaBtcProvider::from_url(opts.polka_btc_url, signer).await?;
    let arc_provider = Arc::new(provider.clone());

    let num_confirmations = if opts.dev { 1 } else { 6 };
    let vault_id = opts.keyring.to_account_id();

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

    let issue_listener = listen_for_issue_requests(arc_provider.clone(), vault_id.clone());
    let redeem_listener = listen_for_redeem_requests(
        arc_provider.clone(),
        btc_rpc.clone(),
        vault_id.clone(),
        num_confirmations,
    );

    let result = tokio::try_join!(
        tokio::spawn(async move {
            issue_listener.await;
        }),
        tokio::spawn(async move {
            redeem_listener.await.unwrap();
        }),
    );
    match result {
        Ok(res) => {
            println!("{:?}", res);
        }
        Err(err) => {
            println!("Error: {}", err);
            std::process::exit(1);
        }
    };

    Ok(())
}

async fn listen_for_issue_requests(provider: Arc<PolkaBtcProvider>, vault_id: AccountId32) {
    let vault_id = &vault_id;
    provider
        .on_event::<RequestIssueEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id == vault_id.clone() {
                    info!("Received issue request #{}", event.issue_id);
                }
            },
            |error| error!("Error reading issue event: {}", error.to_string()),
        )
        .await
        .unwrap();
}

async fn listen_for_redeem_requests(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<BitcoinCore>,
    vault_id: AccountId32,
    num_confirmations: u16,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    provider
        .on_event::<RequestRedeemEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.vault_id != vault_id.clone() {
                    return;
                }
                info!("Received redeem request #{}", event.redeem_id);
                match handle_redeem_request(
                    &event,
                    btc_rpc.clone(),
                    provider.clone(),
                    num_confirmations,
                )
                .await
                {
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
        .await
}

async fn handle_redeem_request(
    event: &RequestRedeemEvent<PolkaBtcRuntime>,
    btc_rpc: Arc<BitcoinCore>,
    arc_provider: Arc<PolkaBtcProvider>,
    num_confirmations: u16,
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
            num_confirmations,
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

fn get_retry_policy() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(MAX_RETRYING_TIME),
        ..Default::default()
    }
}
