use crate::{error::Error, util::*};
use bitcoin::BitcoinCore;
use futures::{stream::StreamExt, SinkExt};
use log::{error, info};
use runtime::{
    pallets::redeem::RequestRedeemEvent, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet,
};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

/// Listen for RequestRedeemEvent directed at this vault; upon reception, send a
/// message to a concurrent task that upon reception will transfer bitcoin and
/// ensures that the on_event callback will not last too long, which would cause
/// the runtime's internal buffer to fill up, and would lead to all future
/// communication failing.
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
    num_confirmations: u16,
) -> Result<(), Error> {
    // create a channel for communication between the two tasks. The buffersize is somewhat arbitrarily chosen
    let (tx, mut rx) = futures::channel::mpsc::channel::<RequestRedeemEvent<PolkaBtcRuntime>>(32);

    let provider_clone = provider.clone();

    // spawn two child tasks
    let result = tokio::try_join!(
        tokio::spawn(async move {
            let tx = &tx;
            let vault_id = &vault_id;
            provider_clone
                .clone()
                .on_event::<RequestRedeemEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if event.vault_id != vault_id.clone() {
                            return;
                        }

                        info!("Received redeem request #{}", event.redeem_id.clone());

                        if let Err(err) = tx.clone().send(event).await {
                            error!("Failed to push redeem event: {}", err);
                        }
                    },
                    |error| error!("Error reading redeem event: {}", error.to_string()),
                )
                .await
        }),
        tokio::spawn(async move {
            loop {
                match rx.next().await {
                    Some(event) => {
                        handle_request_redeem(
                            provider.clone(),
                            btc_rpc.clone(),
                            num_confirmations,
                            event,
                        )
                        .await;
                    }
                    None => {
                        error!("Event stream closed; exiting");
                        return Result::<(), _>::Err(Error::ChannelClosed);
                    }
                }
            }
        })
    )?;
    match result {
        (Err(e), _) => Err(e.into()),
        (_, Err(e)) => Err(e.into()),
        _ => Ok(()),
    }
}

/// Handles the request redeem event: makes the bitcoin transfer and calls execute_redeem.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
/// * `event` - the received event
async fn handle_request_redeem(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<BitcoinCore>,
    num_confirmations: u16,
    event: RequestRedeemEvent<PolkaBtcRuntime>,
) {
    let provider = &provider;

    info!("Processing redeem request #{}", event.redeem_id);

    // prepare the action that will be executed after the bitcoin transfer
    let redeem_id = &event.redeem_id;
    let on_payment = |tx_id, tx_block_height, merkle_proof, raw_tx| async move {
        info!("Executing execute_redeem");
        let ret = provider
            .clone()
            .execute_redeem(*redeem_id, tx_id, tx_block_height, merkle_proof, raw_tx)
            .await;
        info!("ret = {:?}", ret);
        Ok(ret?)
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
}
