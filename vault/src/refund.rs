use crate::{execution::*, system::VaultIdManager};
use bitcoin::BitcoinCoreApi;
use runtime::{InterBtcParachain, RequestRefundEvent};
use service::Error as ServiceError;

/// Listen for RequestRefundEvent directed at this vault; upon reception, transfer
/// bitcoin and call execute_refund
///
/// # Arguments
///
/// * `parachain_rpc` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `network` - network the bitcoin network used (i.e. regtest/testnet/mainnet)
/// * `num_confirmations` - the number of bitcoin confirmation to await
/// * `process_refunds` - if true, we will process refund requests
pub async fn listen_for_refund_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    parachain_rpc: InterBtcParachain,
    btc_rpc: VaultIdManager<B>,
    num_confirmations: u32,
    process_refunds: bool,
) -> Result<(), ServiceError> {
    parachain_rpc
        .on_event::<RequestRefundEvent, _, _, _>(
            |event| async {
                let btc_rpc = match btc_rpc.get_bitcoin_rpc(&event.vault_id).await {
                    Some(x) => x,
                    None => return, // event not directed at this vault
                };
                tracing::info!("Received refund request: {:?}", event);

                if !process_refunds {
                    tracing::info!("Not processing refund");
                    return;
                }

                // within this event callback, we captured the arguments of listen_for_refund_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let parachain_rpc = parachain_rpc.clone();
                let btc_rpc = btc_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                tokio::spawn(async move {
                    tracing::info!("Executing refund #{:?}", event.refund_id);
                    // prepare the action that will be executed after the bitcoin transfer
                    let request = Request::from_refund_request_event(&event);
                    let result = request.pay_and_execute(parachain_rpc, btc_rpc, num_confirmations).await;

                    match result {
                        Ok(_) => tracing::info!(
                            "Completed refund request #{} with amount {}",
                            event.refund_id,
                            event.amount
                        ),
                        Err(e) => tracing::error!(
                            "Failed to process refund request #{}: {}",
                            event.refund_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| tracing::error!("Error reading refund event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}
