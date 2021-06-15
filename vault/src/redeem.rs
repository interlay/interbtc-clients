use crate::execution::*;
use bitcoin::BitcoinCoreApi;
use runtime::{pallets::redeem::RequestRedeemEvent, InterBtcParachain, InterBtcRuntime, RedeemPallet, UtilFuncs};
use service::Error as ServiceError;
use std::time::Duration;

/// Listen for RequestRedeemEvent directed at this vault; upon reception, transfer
/// bitcoin and call execute_redeem
///
/// # Arguments
///
/// * `parachain_rpc` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `network` - network the bitcoin network used (i.e. regtest/testnet/mainnet)
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_redeem_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    parachain_rpc: InterBtcParachain,
    btc_rpc: B,
    num_confirmations: u32,
    payment_margin: Duration,
) -> Result<(), ServiceError> {
    parachain_rpc
        .on_event::<RequestRedeemEvent<InterBtcRuntime>, _, _, _>(
            |event| async {
                if &event.vault_id != parachain_rpc.get_account_id() {
                    return;
                }
                tracing::info!("Received redeem request: {:?}", event);

                // within this event callback, we captured the arguments of listen_for_redeem_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let parachain_rpc = parachain_rpc.clone();
                let btc_rpc = btc_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                tokio::spawn(async move {
                    tracing::info!("Executing redeem #{:?}", event.redeem_id);
                    let result = async {
                        let request = Request::from_redeem_request(
                            event.redeem_id,
                            parachain_rpc.get_redeem_request(event.redeem_id).await?,
                            payment_margin,
                        )?;
                        request.pay_and_execute(parachain_rpc, btc_rpc, num_confirmations).await
                    }
                    .await;

                    match result {
                        Ok(_) => tracing::info!(
                            "Completed redeem request #{} with amount {}",
                            event.redeem_id,
                            event.amount
                        ),
                        Err(e) => tracing::error!(
                            "Failed to process redeem request #{}: {}",
                            event.redeem_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| tracing::error!("Error reading redeem event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}
