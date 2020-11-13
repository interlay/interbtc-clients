use crate::util::*;
use bitcoin::BitcoinCore;
use log::{error, info};
use runtime::{
    pallets::redeem::RequestRedeemEvent, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet,
};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

/// Listen for RequestRedeemEvent directed at this vault; upon reception, transfer
/// bitcoin and call execute_redeem
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `vault_id` - the id of this vault
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_redeem_requests(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<BitcoinCore>,
    vault_id: AccountId32,
    num_confirmations: u32,
) -> Result<(), runtime::Error> {
    provider
        .on_event::<RequestRedeemEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async {
                if event.vault_id != vault_id.clone() {
                    return;
                }
                info!("Received redeem request #{}", event.redeem_id);

                // within this event callback, we captured the arguments of listen_for_redeem_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let provider = provider.clone();
                let btc_rpc = btc_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                tokio::spawn(async move {
                    let provider = &provider;

                    // prepare the action that will be executed after the bitcoin transfer
                    let redeem_id = &event.redeem_id;
                    let on_payment = |tx_id, tx_block_height, merkle_proof, raw_tx| async move {
                        Ok(provider
                            .clone()
                            .execute_redeem(
                                *redeem_id,
                                tx_id,
                                tx_block_height,
                                merkle_proof,
                                raw_tx,
                            )
                            .await?)
                    };

                    let result = execute_payment(
                        btc_rpc.clone(),
                        num_confirmations,
                        event.btc_address,
                        event.amount_polka_btc,
                        event.redeem_id,
                        on_payment,
                    )
                    .await;

                    match result {
                        Ok(_) => info!("Completed redeem request #{}", event.redeem_id),
                        Err(e) => error!(
                            "Failed to process redeem request #{}: {}",
                            event.redeem_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| error!("Error reading redeem event: {}", error.to_string()),
        )
        .await
}
