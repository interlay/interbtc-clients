use crate::{cancellation::RequestEvent, error::Error, execution::Request};
use bitcoin::BitcoinCoreApi;
use futures::{channel::mpsc::Sender, SinkExt};
use log::*;
use runtime::{
    pallets::replace::{AcceptReplaceEvent, AuctionReplaceEvent, ExecuteReplaceEvent, RequestReplaceEvent},
    DotBalancesPallet, PolkaBtcProvider, PolkaBtcRuntime, PolkaBtcVault, ReplacePallet, UtilFuncs, VaultRegistryPallet,
};
use std::time::Duration;
use tokio::time::delay_for;

/// Listen for AcceptReplaceEvent directed at this vault and continue the replacement
/// procedure by transferring bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_accept_replace<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    num_confirmations: u32,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    provider
        .on_event::<AcceptReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.old_vault_id != provider.get_account_id() {
                    return;
                }
                info!("Received accept replace event: {:?}", event);

                // within this event callback, we captured the arguments of listen_for_redeem_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let provider = provider.clone();
                let btc_rpc = btc_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                tokio::spawn(async move {
                    let request = Request::from_accept_replace_event(&event);
                    let result = request.pay_and_execute(provider, btc_rpc, num_confirmations).await;

                    match result {
                        Ok(_) => info!(
                            "Successfully Executed replace #{} with amount {}",
                            event.replace_id, event.amount_btc
                        ),
                        Err(e) => error!(
                            "Failed to process replace request #{}: {}",
                            event.replace_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| error!("Error reading accept_replace_event: {}", error.to_string()),
        )
        .await
}

/// Listen for AuctionReplaceEvent directed at this vault and continue the replacement
/// procedure by transferring bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_auction_replace<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    num_confirmations: u32,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    provider
        .on_event::<AuctionReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.old_vault_id != provider.get_account_id() {
                    return;
                }
                info!("Received auction replace event: {:?}", event);

                // within this event callback, we captured the arguments of listen_for_redeem_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let provider = provider.clone();
                let btc_rpc = btc_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                tokio::spawn(async move {
                    let request = Request::from_auction_replace_event(&event);
                    let result = request.pay_and_execute(provider, btc_rpc, num_confirmations).await;

                    match result {
                        Ok(_) => info!(
                            "Successfully executed auctioned replace #{} with amount {}",
                            event.replace_id, event.btc_amount
                        ),
                        Err(e) => error!(
                            "Failed to process auctioned replace request #{}: {}",
                            event.replace_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| error!("Error reading auction_replace_event: {}", error.to_string()),
        )
        .await
}

/// Listen for RequestReplaceEvent, and attempt to accept it
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `accept_replace_requests` - if true, we attempt to accept replace requests
pub async fn listen_for_replace_requests<B: BitcoinCoreApi + Clone>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    event_channel: Sender<RequestEvent>,
    accept_replace_requests: bool,
) -> Result<(), runtime::Error> {
    let provider = &provider;
    let btc_rpc = &btc_rpc;
    let event_channel = &event_channel;
    provider
        .on_event::<RequestReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.old_vault_id == provider.get_account_id() {
                    // don't respond to requests we placed ourselves
                    return;
                }

                info!(
                    "Received replace request #{} from {} for amount {}",
                    event.replace_id, event.old_vault_id, event.amount_btc
                );

                if accept_replace_requests {
                    match handle_replace_request(provider.clone(), btc_rpc.clone(), &event).await {
                        Ok(_) => {
                            info!("Accepted replace request #{}", event.replace_id);
                            // try to send the event, but ignore the returned result since
                            // the only way it can fail is if the channel is closed
                            let _ = event_channel.clone().send(RequestEvent::Opened).await;
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
pub async fn handle_replace_request<
    B: BitcoinCoreApi + Clone,
    P: DotBalancesPallet + ReplacePallet + VaultRegistryPallet,
>(
    provider: P,
    btc_rpc: B,
    event: &RequestReplaceEvent<PolkaBtcRuntime>,
) -> Result<(), Error> {
    let required_collateral = provider.get_required_collateral_for_polkabtc(event.amount_btc).await?;

    let free_balance = provider.get_free_dot_balance().await?;

    if free_balance < required_collateral {
        Err(Error::InsufficientFunds)
    } else {
        Ok(provider
            .accept_replace(event.replace_id, required_collateral, btc_rpc.get_new_address().await?)
            .await?)
    }
}

/// Monitor the collateralization rate of all vaults and request auctions and auction_replace them
/// when possible.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
/// * `interval` - interval between checks
pub async fn monitor_collateral_of_vaults<B: BitcoinCoreApi + Clone>(
    provider: PolkaBtcProvider,
    btc_rpc: B,
    mut event_channel: Sender<RequestEvent>,
    interval: Duration,
) -> Result<(), runtime::Error> {
    // we could automatically check vault collateralization rates on events
    // that affect this (e.g. `SetExchangeRate`, `WithdrawCollateral`) but
    // polling is easier for now
    loop {
        if let Err(e) = check_collateral_of_vaults(&provider, &btc_rpc, &mut event_channel).await {
            error!("Error while monitoring collateral of vaults: {}", e.to_string());
        }
        delay_for(interval).await
    }
}
/// Monitor the collateralization rate of all vaults and request auctions.
///
/// # Arguments
///
/// * `provider` - the parachain RPC handle
pub async fn check_collateral_of_vaults<B: BitcoinCoreApi + Clone>(
    provider: &PolkaBtcProvider,
    btc_rpc: &B,
    event_channel: &mut Sender<RequestEvent>,
) -> Result<(), Error> {
    let vault_id = provider.get_account_id().clone();
    let vaults = provider
        .get_all_vaults()
        .await?
        .into_iter()
        .filter(|vault| vault.id != vault_id);

    for vault in vaults {
        trace!("Checking collateral of {}", vault.id);
        if provider
            .is_vault_below_auction_threshold(vault.id.clone())
            .await
            .unwrap_or(false)
        {
            match auction_replace(provider, btc_rpc, &vault).await {
                Ok(_) => {
                    info!("Auction replace for vault {} submitted", vault.id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.send(RequestEvent::Opened).await;
                }
                Err(Error::InsufficientFunds) => debug!("Not auctioning vault {}", vault.id),
                Err(e) => error!("Failed to auction vault {}: {}", vault.id, e.to_string()),
            };
        }
    }
    Ok(())
}

async fn auction_replace<B: BitcoinCoreApi + Clone, P: DotBalancesPallet + ReplacePallet + VaultRegistryPallet>(
    provider: &P,
    btc_rpc: &B,
    vault: &PolkaBtcVault,
) -> Result<(), Error> {
    let btc_amount = vault
        .issued_tokens
        .checked_sub(vault.to_be_redeemed_tokens)
        .ok_or(Error::ArithmeticUnderflow)?
        .checked_sub(vault.to_be_replaced_tokens)
        .ok_or(Error::ArithmeticUnderflow)?;
    let collateral = provider.get_required_collateral_for_polkabtc(btc_amount).await?;

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
        .auction_replace(
            vault.id.clone(),
            btc_amount,
            collateral,
            btc_rpc.get_new_address().await?,
        )
        .await?;

    Ok(())
}

/// Listen for ExecuteReplaceEvent directed at this vault and continue the replacement
/// procedure by transferring bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `event_channel` - the channel over which to signal events
pub async fn listen_for_execute_replace(
    provider: PolkaBtcProvider,
    event_channel: Sender<RequestEvent>,
) -> Result<(), runtime::Error> {
    let event_channel = &event_channel;
    let provider = &provider;
    provider
        .on_event::<ExecuteReplaceEvent<PolkaBtcRuntime>, _, _, _>(
            |event| async move {
                if &event.new_vault_id == provider.get_account_id() {
                    info!("Received event: execute replace #{}", event.replace_id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel
                        .clone()
                        .send(RequestEvent::Executed(event.replace_id))
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
    use bitcoin::{
        Block, BlockHash, BlockHeader, Error as BitcoinError, GetBlockResult, LockedTransaction, PartialAddress,
        Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{
        pallets::Core, AccountId, BtcAddress, BtcPublicKey, Error as RuntimeError, H256Le, PolkaBtcReplaceRequest,
        PolkaBtcRuntime, PolkaBtcVault,
    };
    use sp_core::H256;
    use std::time::Duration;

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
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration, num_confirmations: u32) -> Result<BlockHash, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;
            async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, BitcoinError>;
            async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(&self) -> Result<P, BitcoinError>;
            async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
                &self,
                public_key: P,
                secret_key: Vec<u8>,
            ) -> Result<(), BitcoinError>;
            async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError>;
            async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError>;
            async fn get_mempool_transactions<'a>(
                self: &'a Self,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_transaction<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_wallet(&self, wallet: &str) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
                where
                    P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, RuntimeError>;
            async fn register_vault(&self, collateral: u128, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn lock_additional_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, amount: u128) -> Result<(), RuntimeError>;
            async fn update_public_key(&self, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn register_address(&self, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, RuntimeError>;
            async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, RuntimeError>;
        }

        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, amount: u128, griefing_collateral: u128)
                -> Result<H256, RuntimeError>;
            async fn withdraw_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, replace_id: H256, collateral: u128, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn auction_replace(
                &self,
                old_vault: AccountId,
                btc_amount: u128,
                collateral: u128,
                btc_address: BtcAddress,
            ) -> Result<(), RuntimeError>;
            async fn execute_replace(
                &self,
                replace_id: H256,
                tx_id: H256Le,
                merkle_proof: Vec<u8>,
                raw_tx: Vec<u8>,
            ) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(
                &self,
                account_id: AccountId,
            ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn set_replace_period(&self, period: u32) -> Result<(), RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, RuntimeError>;
        }

        #[async_trait]
        pub trait DotBalancesPallet {
            async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn get_free_dot_balance_for_id(&self, id: AccountId) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, RuntimeError>;
            async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), RuntimeError>;
        }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    #[tokio::test]
    async fn test_handle_auction_replace_with_insufficient_collateral() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_get_new_address().returning(|| Ok(BtcAddress::default()));

        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_polkabtc()
            .returning(|_| Ok(100));
        provider.expect_get_free_dot_balance().returning(|| Ok(50));

        let vault = PolkaBtcVault::default();
        assert_err!(
            auction_replace(&provider, &bitcoin, &vault).await,
            Error::InsufficientFunds
        );
    }

    #[tokio::test]
    async fn test_handle_replace_request_with_insufficient_balance() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_get_new_address().returning(|| Ok(BtcAddress::default()));

        let mut provider = MockProvider::default();
        provider
            .expect_get_required_collateral_for_polkabtc()
            .returning(|_| Ok(100));
        provider.expect_get_free_dot_balance().returning(|| Ok(50));

        let event = RequestReplaceEvent {
            amount_btc: Default::default(),
            old_vault_id: Default::default(),
            replace_id: Default::default(),
            griefing_collateral: Default::default(),
        };
        assert_err!(
            handle_replace_request(provider, bitcoin, &event).await,
            Error::InsufficientFunds
        );
    }
}
