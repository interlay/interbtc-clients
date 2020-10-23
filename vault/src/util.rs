use crate::error::Error;
use backoff::{future::FutureOperation as _, ExponentialBackoff};
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use log::info;
use runtime::H256Le;
use sp_core::{H160, H256};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

// keep trying for 24 hours
const MAX_RETRYING_TIME: Duration = Duration::from_secs(24 * 60 * 60);

/// First makes bitcoin transfer, then calls tries to call on_payment until it 
/// succeeds
///
/// # Arguments
///
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
/// * `btc_address` the destination address
/// * `amount_polka_btc` amount of btc to send
/// * `event_id` the nonce to incorporate with op_return into the transaction
/// * `on_payment` callback that is called after bitcoin transfer succeeds
///                until it succeeds
pub async fn execute_payment<F, R>(
    btc_rpc: Arc<BitcoinCore>,
    num_confirmations: u16,
    btc_address: H160,
    amount_polka_btc: u128,
    event_id: H256,
    on_payment: F,
) -> Result<(), Error>
where
    F: Fn(H256Le, u32, Vec<u8>, Vec<u8>) -> R,
    R: Future<Output = Result<(), Error>>,
{
    let address = bitcoin::hash_to_p2wpkh(btc_address, bitcoin::Network::Regtest)
        .map_err(|e| -> bitcoin::Error { e.into() })?;

    info!("Sending bitcoin to {}", btc_address);

    // Step 1: make bitcoin transfer. Note: do not retry this call;
    // the call could fail to get the metadata even if the transaction
    // itself was successful
    let tx_metadata = btc_rpc
        .send_to_address(
            address.clone(),
            amount_polka_btc as u64,
            &event_id.to_fixed_bytes(),
            MAX_RETRYING_TIME,
            num_confirmations,
        )
        .await?;

    info!("Bitcoin successfully sent to {}", btc_address);

    // step 2: try callback until it succeeds or times out
    // For now, this is either execute_redeem or execute_replace
    (|| async {
        Ok(on_payment(
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

/// gets our default retrying policy
pub fn get_retry_policy() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(MAX_RETRYING_TIME),
        ..Default::default()
    }
}
