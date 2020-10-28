use crate::error::Error;
use crate::util::*;
use backoff::future::FutureOperation as _;
use bitcoin::BitcoinCore;
use log::{error, info};
use runtime::{
    pallets::{
        replace::{AcceptReplaceEvent, RequestReplaceEvent},
        vault_registry::Vault,
    },
    PolkaBtcProvider, PolkaBtcRuntime, ReplacePallet, VaultRegistryPallet
};
use sp_core::crypto::AccountId32;
use std::sync::Arc;

/// Listen for AcceptReplaceEvent directed at this vault and continue the replacement
/// procedure by transfering bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `vault_id` - the id of this vault
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_accept_replace(
    provider: Arc<PolkaBtcProvider>,
    btc_rpc: Arc<BitcoinCore>,
    vault_id: AccountId32,
    num_confirmations: u16,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    provider
        .on_event::<AcceptReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.old_vault_id != vault_id.clone() {
                    return;
                }
                info!("Received replace request #{}", event.replace_id);

                let result = handle_accepted_replace_request(
                    &event,
                    btc_rpc.clone(),
                    provider.clone(),
                    num_confirmations,
                )
                .await;

                match result {
                    Ok(_) => info!("Successfully Executed replace #{}", event.replace_id),
                    Err(e) => error!(
                        "Failed to process replace request #{}: {}",
                        event.replace_id,
                        e.to_string()
                    ),
                }
            },
            |error| error!("Error reading redeem event: {}", error.to_string()),
        )
        .await
}

pub async fn handle_accepted_replace_request(
    event: &AcceptReplaceEvent<PolkaBtcRuntime>,
    btc_rpc: Arc<BitcoinCore>,
    provider: Arc<PolkaBtcProvider>,
    num_confirmations: u16,
) -> Result<(), Error> {
    let provider = &provider;

    // retrieve vault's btc address
    let Vault { btc_address, .. } =
        (|| async { Ok(provider.get_vault(event.new_vault_id.clone()).await?) })
            .retry(get_retry_policy())
            .await?;

    // prepare the action that is to be run after transfering bitcoin
    let replace_id = &event.replace_id;
    let execute_replace = |tx_id, tx_block_height, merkle_proof, raw_tx| async move {
        Ok(provider
            .clone()
            .execute_replace(*replace_id, tx_id, tx_block_height, merkle_proof, raw_tx)
            .await?)
    };

    // first makes bitcoin payment, then calls execute_replace
    execute_payment(
        btc_rpc.clone(),
        num_confirmations,
        btc_address,
        event.btc_amount,
        event.replace_id,
        execute_replace,
    )
    .await
}

/// Listen for RequestReplaceEvent, and attempt to accept it
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `vault_id` - the id of this vault
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_replace_requests(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let vault_id = &vault_id;
    provider
        .on_event::<RequestReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.old_vault_id == vault_id.clone() {
                    // don't respond to requests we placed ourselves
                    return;
                }

                info!(
                    "Received replace request #{} from {}",
                    event.replace_id, event.old_vault_id
                );

                match handle_replace_request(provider.clone(), &event).await
                {
                    Ok(_) => info!("Accepted replace request #{}", event.replace_id),
                    Err(e) => error!(
                        "Failed to accept replace request #{}: {}",
                        event.replace_id,
                        e.to_string()
                    ),
                }
            },
            |error| error!("Error reading replace event: {}", error.to_string()),
        )
        .await
}

/// Attempts to accept a replace request. Does not retry RPC calls upon
/// failure, since nothing is at stake at this point
pub async fn handle_replace_request(
    provider: Arc<PolkaBtcProvider>,
    event: &RequestReplaceEvent<PolkaBtcRuntime>,
) -> Result<(), Error> {
    let required_collateral = provider
        .get_required_collateral_for_polkabtc(event.amount)
        .await?;

    // If this fails, we probably don't have enough dots to place the required collateral.
    provider
        .accept_replace(event.replace_id, required_collateral) // todo: determine safe collateral
        .await?;

    Ok(())
}
