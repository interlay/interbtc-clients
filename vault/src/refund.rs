use crate::{execution::*, storage::TransactionStore, system::VaultIdManager};
use bitcoin::BitcoinCoreApi;
use runtime::{InterBtcParachain, RequestRefundEvent};
use service::{spawn_cancelable, Error as ServiceError, ShutdownSender};
use std::sync::Arc;

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
pub async fn listen_for_refund_requests<B, TS>(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
    tx_store: Arc<TS>,
    num_confirmations: u32,
    process_refunds: bool,
) -> Result<(), ServiceError>
where
    B: BitcoinCoreApi + Clone + Send + Sync + 'static,
    TS: TransactionStore + Send + Sync + 'static,
{
    parachain_rpc
        .on_event::<RequestRefundEvent, _, _, _>(
            |event| async {
                let vault = match vault_id_manager.get_vault(&event.vault_id).await {
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
                let tx_store = tx_store.clone();
                // Spawn a new task so that we handle these events concurrently
                spawn_cancelable(shutdown_tx.subscribe(), async move {
                    tracing::info!("Executing refund #{:?}", event.refund_id);
                    // prepare the action that will be executed after the bitcoin transfer
                    let request = Request::from_refund_request_event(&event);
                    let result = request
                        .pay_and_execute(parachain_rpc, vault, tx_store, num_confirmations)
                        .await;

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
