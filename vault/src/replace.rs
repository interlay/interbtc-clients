use crate::{cancellation::Event, error::Error, execution::Request, system::VaultIdManager};
use bitcoin::BitcoinCoreApi;
use futures::{channel::mpsc::Sender, future::try_join3, SinkExt};
use runtime::{
    AcceptReplaceEvent, CollateralBalancesPallet, ExecuteReplaceEvent, InterBtcParachain, ReplacePallet,
    RequestReplaceEvent, UtilFuncs, VaultId, VaultRegistryPallet,
};
use service::{spawn_cancelable, Error as ServiceError, ShutdownSender};
use std::time::Duration;

/// Listen for AcceptReplaceEvent directed at this vault and continue the replacement
/// procedure by transferring bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `parachain_rpc` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_accept_replace<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    btc_rpc: VaultIdManager<B>,
    num_confirmations: u32,
    payment_margin: Duration,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let btc_rpc = &btc_rpc;
    let shutdown_tx = &shutdown_tx;
    parachain_rpc
        .on_event::<AcceptReplaceEvent, _, _, _>(
            |event| async move {
                let btc_rpc = match btc_rpc.get_bitcoin_rpc(&event.old_vault_id).await {
                    Some(x) => x,
                    None => return, // event not directed at this vault
                };
                tracing::info!("Received accept replace event: {:?}", event);

                // within this event callback, we captured the arguments of listen_for_redeem_requests
                // by reference. Since spawn requires static lifetimes, we will need to capture the
                // arguments by value rather than by reference, so clone these:
                let parachain_rpc = parachain_rpc.clone();
                // Spawn a new task so that we handle these events concurrently
                spawn_cancelable(shutdown_tx.subscribe(), async move {
                    tracing::info!("Executing accept replace #{:?}", event.replace_id);

                    let result = async {
                        let request = Request::from_replace_request(
                            event.replace_id,
                            parachain_rpc.get_replace_request(event.replace_id).await?,
                            payment_margin,
                        )?;
                        request.pay_and_execute(parachain_rpc, btc_rpc, num_confirmations).await
                    }
                    .await;

                    match result {
                        Ok(_) => tracing::info!(
                            "Completed accept replace request #{} with amount {}",
                            event.replace_id,
                            event.amount
                        ),
                        Err(e) => tracing::error!(
                            "Failed to process accept replace request #{}: {}",
                            event.replace_id,
                            e.to_string()
                        ),
                    }
                });
            },
            |error| tracing::error!("Error reading accept_replace_event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

/// Listen for RequestReplaceEvent, and attempt to accept it
///
/// # Arguments
///
/// * `parachain_rpc` - the parachain RPC handle
/// * `event_channel` - the channel over which to signal events
/// * `accept_replace_requests` - if true, we attempt to accept replace requests
pub async fn listen_for_replace_requests<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    parachain_rpc: InterBtcParachain,
    btc_rpc: VaultIdManager<B>,
    event_channel: Sender<Event>,
    accept_replace_requests: bool,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let btc_rpc = &btc_rpc;
    let event_channel = &event_channel;
    parachain_rpc
        .on_event::<RequestReplaceEvent, _, _, _>(
            |event| async move {
                if parachain_rpc.is_this_vault(&event.old_vault_id) {
                    // don't respond to requests we placed ourselves
                    return;
                }

                tracing::info!(
                    "Received replace request from {} for amount {}",
                    event.old_vault_id.pretty_printed(),
                    event.amount
                );

                if accept_replace_requests {
                    for (vault_id, btc_rpc) in btc_rpc.get_vault_btc_rpcs().await {
                        match handle_replace_request(parachain_rpc.clone(), btc_rpc.clone(), &event, &vault_id).await {
                            Ok(_) => {
                                tracing::info!(
                                    "[{}] Accepted replace request from {}",
                                    vault_id.pretty_printed(),
                                    event.old_vault_id.pretty_printed()
                                );
                                // try to send the event, but ignore the returned result since
                                // the only way it can fail is if the channel is closed
                                let _ = event_channel.clone().send(Event::Opened).await;

                                return; // no need to iterate over the rest of the vault ids
                            }
                            Err(e) => tracing::error!(
                                "[{}] Failed to accept replace request from {}: {}",
                                vault_id.pretty_printed(),
                                event.old_vault_id.pretty_printed(),
                                e.to_string()
                            ),
                        }
                    }
                }
            },
            |error| tracing::error!("Error reading replace event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

/// Attempts to accept a replace request. Does not retry RPC calls upon
/// failure, since nothing is at stake at this point
pub async fn handle_replace_request<
    B: BitcoinCoreApi + Clone,
    P: CollateralBalancesPallet + ReplacePallet + VaultRegistryPallet,
>(
    parachain_rpc: P,
    btc_rpc: B,
    event: &RequestReplaceEvent,
    vault_id: &VaultId,
) -> Result<(), Error> {
    let collateral_currency = vault_id.collateral_currency();
    let (required_collateral, free_balance, minimum_replace) = try_join3(
        parachain_rpc.get_required_collateral_for_wrapped(event.amount, collateral_currency),
        parachain_rpc.get_free_balance(collateral_currency),
        parachain_rpc.get_replace_dust_amount(),
    )
    .await?;

    if required_collateral <= minimum_replace {
        Err(Error::BelowDustAmount)
    } else if free_balance < required_collateral {
        Err(Error::InsufficientFunds)
    } else {
        Ok(parachain_rpc
            .accept_replace(
                vault_id,
                &event.old_vault_id,
                event.amount,
                required_collateral,
                btc_rpc.get_new_address().await?,
            )
            .await?)
    }
}

/// Listen for ExecuteReplaceEvent directed at this vault and continue the replacement
/// procedure by transferring bitcoin and calling execute_replace
///
/// # Arguments
///
/// * `event_channel` - the channel over which to signal events
pub async fn listen_for_execute_replace(
    parachain_rpc: InterBtcParachain,
    event_channel: Sender<Event>,
) -> Result<(), ServiceError> {
    let event_channel = &event_channel;
    let parachain_rpc = &parachain_rpc;
    parachain_rpc
        .on_event::<ExecuteReplaceEvent, _, _, _>(
            |event| async move {
                if &event.new_vault_id.account_id == parachain_rpc.get_account_id() {
                    tracing::info!("Received event: execute replace #{:?}", event.replace_id);
                    // try to send the event, but ignore the returned result since
                    // the only way it can fail is if the channel is closed
                    let _ = event_channel.clone().send(Event::Executed(event.replace_id)).await;
                }
            },
            |error| tracing::error!("Error reading redeem event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

#[cfg(all(test, feature = "standalone-metadata"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        json, Amount, Block, BlockHash, BlockHeader, Error as BitcoinError, GetBlockResult, LockedTransaction, Network,
        PartialAddress, PrivateKey, Transaction, TransactionMetadata, Txid, PUBLIC_KEY_SIZE,
    };
    use runtime::{
        AccountId, Balance, BtcAddress, BtcPublicKey, CurrencyId, Error as RuntimeError, InterBtcReplaceRequest,
        InterBtcVault, Token, DOT, H256, INTERBTC,
    };

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
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError>;
            async fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError>;
            async fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
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
                &'a self,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_transaction<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<LockedTransaction, BitcoinError>;
            async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError>;
            async fn create_and_send_transaction<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
            ) -> Result<Txid, BitcoinError>;
            async fn send_to_address<A: PartialAddress + Send + Sync + 'static>(
                &self,
                address: A,
                sat: u64,
                request_id: Option<H256>,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
            async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, BitcoinError>
                where
                    P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;
            async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), BitcoinError>;
            async fn rescan_blockchain(&self, start_height: usize) -> Result<(), BitcoinError>;
            async fn find_duplicate_payments(&self, transaction: &Transaction) -> Result<Vec<(Txid, BlockHash)>, BitcoinError>;
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
        async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, RuntimeError>;
        async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, RuntimeError>;
        async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, RuntimeError>;
        async fn register_vault(&self, vault_id: &VaultId, collateral: u128, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
        async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
        async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
        async fn update_public_key(&self, vault_id: &VaultId, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
        async fn register_address(&self, vault_id: &VaultId, btc_address: BtcAddress) -> Result<(), RuntimeError>;
        async fn get_required_collateral_for_wrapped(&self, amount_btc: u128, collateral_currency: CurrencyId) -> Result<u128, RuntimeError>;
        async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
        async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
        async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
    }

    #[async_trait]
    pub trait ReplacePallet {
        async fn request_replace(&self, vault_id: &VaultId, amount: u128, griefing_collateral: u128) -> Result<(), RuntimeError>;
        async fn withdraw_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
        async fn accept_replace(&self, new_vault: &VaultId, old_vault: &VaultId, amount_btc: u128, collateral: u128, btc_address: BtcAddress) -> Result<(), RuntimeError>;
        async fn execute_replace(&self, replace_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), RuntimeError>;
        async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
        async fn get_new_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
        async fn get_old_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
        async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
        async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, RuntimeError>;
        async fn get_replace_dust_amount(&self) -> Result<u128, RuntimeError>;
    }


    #[async_trait]
    pub trait CollateralBalancesPallet {
        async fn get_free_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
        async fn get_free_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
        async fn get_reserved_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
        async fn get_reserved_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
        async fn transfer_to(&self, recipient: &AccountId, amount: u128, currency_id: CurrencyId) -> Result<(), RuntimeError>;         }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(INTERBTC))
    }

    #[tokio::test]
    async fn test_handle_replace_request_with_insufficient_balance() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin.expect_get_new_address().returning(|| Ok(BtcAddress::default()));

        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_required_collateral_for_wrapped()
            .returning(|_, _| Ok(100));
        parachain_rpc.expect_get_free_balance().returning(|_| Ok(50));
        parachain_rpc
            .expect_get_replace_dust_amount()
            .times(1)
            .returning(|| Ok(0));

        let event = RequestReplaceEvent {
            old_vault_id: dummy_vault_id(),
            amount: Default::default(),
            griefing_collateral: Default::default(),
        };
        assert_err!(
            handle_replace_request(parachain_rpc, bitcoin, &event, &dummy_vault_id()).await,
            Error::InsufficientFunds
        );
    }
}
