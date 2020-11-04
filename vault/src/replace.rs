use crate::error::Error;
use crate::scheduler::ProcessEvent;
use crate::util::*;
use backoff::future::FutureOperation as _;
use bitcoin::BitcoinCore;
use futures::channel::mpsc::Sender;
use futures::SinkExt;
use log::{error, info, trace};
use runtime::{
    pallets::{
        replace::{AcceptReplaceEvent, ExecuteReplaceEvent, RequestReplaceEvent},
        vault_registry::Vault,
    },
    DotBalancesPallet, PolkaBtcProvider, PolkaBtcRuntime, PolkaBtcVault, ReplacePallet,
    VaultRegistryPallet,
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
                info!("Replace request #{} was accepted", event.replace_id);

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

/// Performs the required actions when our replace request was accepted:
/// it makes the bitcoin payment to the new vault and then executes the
/// replace.
///
/// # Arguments
///
/// * `event` - the event we are acting upon
/// * `btc_rpc` - the bitcoin RPC handle
/// * `provider` - the parachain RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn handle_accepted_replace_request(
    event: &AcceptReplaceEvent<PolkaBtcRuntime>,
    btc_rpc: Arc<BitcoinCore>,
    provider: Arc<PolkaBtcProvider>,
    num_confirmations: u16,
) -> Result<(), Error> {
    let provider = &provider;

    // retrieve vault's btc address
    let Vault { wallet, .. } =
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
        wallet.get_btc_address(),
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
/// * `vault_id` - the id of this vault
/// * `event_channel` - the channel over which to signal events
/// * `accept_replace_requests` - if true, we attempt to accept replace requests
pub async fn listen_for_replace_requests(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<ProcessEvent>,
    accept_replace_requests: bool,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let vault_id = &vault_id;
    let event_channel = &event_channel;
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

                if accept_replace_requests {
                    match handle_replace_request(provider.clone(), &event).await {
                        Ok(_) => {
                            info!("Accepted replace request #{}", event.replace_id);
                            // try to send the event, but ignore the returned result since
                            // the only way it can fail is if the channel is closed
                            let _ = event_channel.clone().send(ProcessEvent::Opened).await;
                        }
                        Err(e) => error!(
                            "Failed to accept replace request #{}: {}",
                            event.replace_id,
                            e.to_string()
                        ),
                    }
                }
            },
            |error| error!("Error reading replace event: {}", error.to_string()),
        )
        .await
}

/// Attempts to accept a replace request. Does not retry RPC calls upon
/// failure, since nothing is at stake at this point
pub async fn handle_replace_request<P: DotBalancesPallet + ReplacePallet + VaultRegistryPallet>(
    provider: Arc<P>,
    event: &RequestReplaceEvent<PolkaBtcRuntime>,
) -> Result<(), Error> {
    let required_collateral = provider
        .get_required_collateral_for_polkabtc(event.amount)
        .await?;

    let free_balance = provider.get_free_dot_balance().await?;

    if free_balance < required_collateral {
        Err(Error::InsufficientFunds)
    } else {
        Ok(provider
            .accept_replace(event.replace_id, required_collateral)
            .await?)
    }
}

/// Monitor the collateralization rate of all vaults and request auctions.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
pub async fn monitor_collateral_of_vaults(provider: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    for vault in provider.get_all_vaults().await? {
        trace!("Checking collateral of {}", vault.id);
        if vault.id == provider.get_account_id().clone() {
            continue;
        } else if provider
            .is_vault_below_auction_threshold(vault.id.clone())
            .await
            .unwrap_or(false)
        {
            match handle_auction_replace(&provider, &vault).await {
                Ok(_) => info!("Auction replace for vault {} submitted", vault.id),
                Err(e) => error!("Failed to auction vault {}: {}", vault.id, e.to_string()),
            };
        }
    }
    Ok(())
}

async fn handle_auction_replace<P: DotBalancesPallet + ReplacePallet + VaultRegistryPallet>(
    provider: &Arc<P>,
    vault: &PolkaBtcVault,
) -> Result<(), Error> {
    let btc_amount = vault.issued_tokens;
    let collateral = provider
        .get_required_collateral_for_polkabtc(btc_amount)
        .await?;

    // don't auction vault if we can't afford to replace it
    if collateral > provider.get_free_dot_balance().await? {
        return Err(Error::InsufficientFunds);
    }

    info!(
        "Vault {} is below auction threshold; replacing {} BTC with {} DOT",
        vault.id, btc_amount, collateral
    );

    // TODO: retry auctioning?
    provider
        .auction_replace(vault.id.clone(), btc_amount, collateral)
        .await?;

    Ok(())
}

/// Listen for ExecuteReplaceEvent directed at this vault and continue the replacement
/// procedure by transfering bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `vault_id` - the id of this vault
/// * `event_channel` - the channel over which to signal events
pub async fn listen_for_execute_replace(
    provider: Arc<PolkaBtcProvider>,
    vault_id: AccountId32,
    event_channel: Sender<ProcessEvent>,
) -> Result<(), runtime::Error> {
    let vault_id = &vault_id;
    let event_channel = &event_channel;
    provider
        .on_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if event.new_vault_id == vault_id.clone() {
                    info!("Received event: execute replace #{}", event.replace_id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel
                        .clone()
                        .send(ProcessEvent::Executed(event.replace_id))
                        .await;
                }
            },
            |error| error!("Error reading redeem event: {}", error.to_string()),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use runtime::{
        pallets::Core, AccountId, Error as RuntimeError, H256Le, PolkaBtcReplaceRequest,
        PolkaBtcRuntime, PolkaBtcVault,
    };
    use sp_core::{H160, H256};

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, RuntimeError>;
            async fn register_vault(&self, collateral: u128, btc_address: H160) -> Result<(), RuntimeError>;
            async fn lock_additional_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn update_btc_address(&self, address: H160) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, RuntimeError>;
            async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, RuntimeError>;
        }

        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, amount: u128, griefing_collateral: u128)
                -> Result<H256, RuntimeError>;
            async fn withdraw_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, replace_id: H256, collateral: u128) -> Result<(), RuntimeError>;
            async fn auction_replace(
                &self,
                old_vault: AccountId,
                btc_amount: u128,
                collateral: u128,
            ) -> Result<(), RuntimeError>;
            async fn execute_replace(
                &self,
                replace_id: H256,
                tx_id: H256Le,
                tx_block_height: u32,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
        }

        #[async_trait]
        pub trait DotBalancesPallet {
            async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
        }
    }

    #[tokio::test]
    async fn test_handle_auction_replace_with_insufficient_collateral() {
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_polkabtc()
            .returning(|_| Ok(100));
        provider.expect_get_free_dot_balance().returning(|| Ok(50));

        let vault = PolkaBtcVault::default();
        assert_err!(
            handle_auction_replace(&Arc::new(provider), &vault).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_handle_replace_request_with_insufficient_balance() {
        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_polkabtc()
            .returning(|_| Ok(100));
        provider.expect_get_free_dot_balance().returning(|| Ok(50));

        let event = RequestReplaceEvent {
            amount: Default::default(),
            old_vault_id: Default::default(),
            replace_id: Default::default(),
        };
        assert_err!(
            handle_replace_request(Arc::new(provider), &event).await,
            Error::InsufficientFunds
        );
    }
}
