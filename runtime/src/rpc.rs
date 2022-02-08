use crate::{
    conn::{new_websocket_client, new_websocket_client_with_retry},
    metadata,
    metadata::DispatchError,
    notify_retry,
    types::*,
    AccountId, CurrencyId, Error, InterBtcRuntime, InterBtcSigner, RetryPolicy, RichH256Le, SubxtError,
};
#[cfg(any(feature = "standalone-metadata", feature = "parachain-metadata-testnet"))]
use crate::{BTC_RELAY_MODULE, STABLE_BITCOIN_CONFIRMATIONS, STABLE_PARACHAIN_CONFIRMATIONS};
use async_trait::async_trait;
use codec::Encode;
use futures::{future::join_all, stream::StreamExt, FutureExt, SinkExt};
use jsonrpsee::core::to_json_value;
use module_oracle_rpc_runtime_api::BalanceWrapper;
use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};
use subxt::{
    BasicError, Client as SubxtClient, ClientBuilder as SubxtClientBuilder, DefaultExtra, Event, EventSubscription,
    EventsDecoder, Metadata, RpcClient, Signer, TransactionEvents, TransactionProgress,
};
use tokio::{sync::RwLock, time::sleep};

cfg_if::cfg_if! {
    if #[cfg(feature = "standalone-metadata")] {
        const DEFAULT_SPEC_VERSION: u32 = 1;
    } else if #[cfg(feature = "parachain-metadata-kintsugi")] {
        const DEFAULT_SPEC_VERSION: u32 = 9;
    } else if #[cfg(feature = "parachain-metadata-testnet")] {
        const DEFAULT_SPEC_VERSION: u32 = 0;
    }
}

type RuntimeApi = metadata::RuntimeApi<InterBtcRuntime, DefaultExtra<InterBtcRuntime>>;

#[derive(Clone)]
pub struct InterBtcParachain {
    rpc_client: RpcClient,
    ext_client: SubxtClient<InterBtcRuntime>,
    signer: Arc<RwLock<InterBtcSigner>>,
    account_id: AccountId,
    api: Arc<RuntimeApi>,
    metadata: Arc<Metadata>,
    pub native_currency_id: CurrencyId,
    pub relay_chain_currency_id: CurrencyId,
    pub wrapped_currency_id: CurrencyId,
}

impl InterBtcParachain {
    pub async fn new<P: Into<RpcClient>>(rpc_client: P, signer: InterBtcSigner) -> Result<Self, Error> {
        let account_id = signer.account_id().clone();
        let rpc_client = rpc_client.into();
        let ext_client = SubxtClientBuilder::new().set_client(rpc_client.clone()).build().await?;
        let api: RuntimeApi = ext_client.clone().to_runtime_api();
        let metadata = Arc::new(ext_client.rpc().metadata().await?);

        let runtime_version = ext_client.rpc().runtime_version(None).await?;
        if runtime_version.spec_version == DEFAULT_SPEC_VERSION {
            log::info!("spec_version={}", runtime_version.spec_version);
            log::info!("transaction_version={}", runtime_version.transaction_version);
        } else {
            return Err(Error::InvalidSpecVersion(
                DEFAULT_SPEC_VERSION,
                runtime_version.spec_version,
            ));
        }

        let currency_constants = api.constants().currency();
        let native_currency_id = currency_constants.get_native_currency_id()?;
        let relay_chain_currency_id = currency_constants.get_relay_chain_currency_id()?;
        let wrapped_currency_id = currency_constants.get_wrapped_currency_id()?;

        let parachain_rpc = Self {
            rpc_client,
            ext_client,
            api: Arc::new(api),
            metadata,
            signer: Arc::new(RwLock::new(signer)),
            account_id,
            native_currency_id,
            relay_chain_currency_id,
            wrapped_currency_id,
        };
        parachain_rpc.refresh_nonce().await;
        Ok(parachain_rpc)
    }

    pub async fn from_url(url: &str, signer: InterBtcSigner) -> Result<Self, Error> {
        let ws_client = new_websocket_client(url, None, None).await?;
        Self::new(ws_client, signer).await
    }

    pub async fn from_url_with_retry(
        url: &str,
        signer: InterBtcSigner,
        connection_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::from_url_and_config_with_retry(url, signer, None, None, connection_timeout).await
    }

    pub async fn from_url_and_config_with_retry(
        url: &str,
        signer: InterBtcSigner,
        max_concurrent_requests: Option<usize>,
        max_notifs_per_subscription: Option<usize>,
        connection_timeout: Duration,
    ) -> Result<Self, Error> {
        let ws_client = new_websocket_client_with_retry(
            url,
            max_concurrent_requests,
            max_notifs_per_subscription,
            connection_timeout,
        )
        .await?;
        Self::new(ws_client, signer).await
    }

    async fn refresh_nonce(&self) {
        let mut signer = self.signer.write().await;
        // For getting the nonce, use latest, possibly non-finalized block.
        // TODO: we might want to wait until the latest block is actually finalized
        // query account info in order to get the nonce value used for communication
        let account_info = self
            .api
            .storage()
            .system()
            .account(self.account_id.clone(), None)
            .await
            .map(|x| x.nonce)
            .unwrap_or(0);

        log::info!("Refreshing nonce: {}", account_info);
        signer.set_nonce(account_info);
    }

    /// Gets a copy of the signer with a unique nonce
    async fn with_unique_signer<'client, F, R>(&self, call: F) -> Result<TransactionEvents<InterBtcRuntime>, Error>
    where
        F: Fn(InterBtcSigner) -> R,
        R: Future<Output = Result<TransactionProgress<'client, InterBtcRuntime, DispatchError>, BasicError>>,
    {
        notify_retry::<Error, _, _, _, _, _>(
            || async {
                let signer = {
                    let mut signer = self.signer.write().await;
                    // return the current value, increment afterwards
                    let cloned_signer = signer.clone();
                    signer.increment_nonce();
                    cloned_signer
                };
                Ok(call(signer).await?.wait_for_finalized_success().await?)
            },
            |result| async {
                match result.map_err(Into::<Error>::into) {
                    Ok(te) => Ok(te),
                    Err(err) if err.is_invalid_transaction() => {
                        self.refresh_nonce().await;
                        Err(RetryPolicy::Skip(Error::InvalidTransaction))
                    }
                    Err(err) => Err(RetryPolicy::Throw(err)),
                }
            },
        )
        .await
    }

    pub async fn get_latest_block_hash(&self) -> Result<Option<H256>, Error> {
        Ok(Some(self.ext_client.rpc().finalized_head().await?))
    }

    /// Subscribe to new parachain blocks.
    pub async fn on_block<F, R>(&self, on_block: F) -> Result<(), Error>
    where
        F: Fn(InterBtcHeader) -> R,
        R: Future<Output = Result<(), Error>>,
    {
        let mut sub = self.ext_client.rpc().subscribe_finalized_blocks().await?;
        loop {
            on_block(sub.next().await.ok_or(Error::ChannelClosed)??).await?;
        }
    }

    /// Subscription service that should listen forever, only returns if the initial subscription
    /// cannot be established. Calls `on_error` when an error event has been received, or when an
    /// event has been received that failed to be decoded into a raw event.
    ///
    /// # Arguments
    /// * `on_error` - callback for decoding errors, is not allowed to take too long
    pub async fn on_event_error<E: Fn(BasicError)>(&self, on_error: E) -> Result<(), Error> {
        let sub = self.ext_client.rpc().subscribe_finalized_events().await?;
        let decoder = EventsDecoder::<InterBtcRuntime>::new((*self.metadata).clone());

        let mut sub = EventSubscription::<InterBtcRuntime>::new(sub, &decoder);
        loop {
            match sub.next().await {
                Some(Err(err)) => on_error(err), // report error
                Some(Ok(_)) => {}                // do nothing
                None => break Ok(()),            // end of stream
            }
        }
    }

    /// Subscription service that should listen forever, only returns if the initial subscription
    /// cannot be established. This function uses two concurrent tasks: one for the event listener,
    /// and one that calls the given callback. This allows the callback to take a long time to
    /// complete without breaking the rpc communication, which could otherwise happen. Still, since
    /// the queue of callbacks is processed sequentially, some care should be taken that the queue
    /// does not overflow. `on_error` is called when the event has successfully been decoded into a
    /// raw_event, but failed to decode into an event of type `T`
    ///
    /// # Arguments
    /// * `on_event` - callback for events, is allowed to sometimes take a longer time
    /// * `on_error` - callback for decoding error, is not allowed to take too long
    pub async fn on_event<T, F, R, E>(&self, mut on_event: F, on_error: E) -> Result<(), Error>
    where
        T: Event + core::fmt::Debug,
        F: FnMut(T) -> R,
        R: Future<Output = ()>,
        E: Fn(SubxtError),
    {
        let sub = self.ext_client.rpc().subscribe_finalized_events().await?;
        let decoder = EventsDecoder::<InterBtcRuntime>::new((*self.metadata).clone());

        let mut sub = EventSubscription::<InterBtcRuntime>::new(sub, &decoder);
        sub.filter_event::<T>();

        let (tx, mut rx) = futures::channel::mpsc::channel::<T>(32);

        // two tasks: one for event listening and one for callback calling
        futures::future::try_join(
            async move {
                let tx = &tx;
                while let Some(result) = sub.next().fuse().await {
                    if let Ok(raw_event) = result {
                        log::trace!("raw event: {:?}", raw_event);
                        let decoded = T::decode(&mut &raw_event.data[..]);
                        match decoded {
                            Ok(event) => {
                                log::trace!("decoded event: {:?}", event);
                                // send the event to the other task
                                if tx.clone().send(event).await.is_err() {
                                    break;
                                }
                            }
                            Err(err) => {
                                on_error(err.into());
                            }
                        };
                    }
                }
                Result::<(), _>::Err(Error::ChannelClosed)
            },
            async move {
                loop {
                    // block until we receive an event from the other task
                    match rx.next().fuse().await {
                        Some(event) => {
                            on_event(event).await;
                        }
                        None => {
                            return Result::<(), _>::Err(Error::ChannelClosed);
                        }
                    }
                }
            },
        )
        .await?;

        Ok(())
    }

    async fn batch(&self, calls: Vec<EncodedCall>) -> Result<(), Error> {
        let encoded_calls = &calls;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .utility()
                .batch(encoded_calls.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    #[cfg(test)]
    pub async fn get_outdated_nonce_error(&self) -> Error {
        use sp_arithmetic::FixedPointNumber;

        let key = OracleKey::ExchangeRate(Token(DOT));
        let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);

        let mut signer = self.signer.write().await;

        self.api
            .tx()
            .oracle()
            .feed_values(vec![(key.clone(), exchange_rate)])
            .sign_and_submit_then_watch(&signer.clone())
            .await
            .unwrap();

        signer.set_nonce(0);

        // now call with outdated nonce
        self.api
            .tx()
            .oracle()
            .feed_values(vec![(key, exchange_rate)])
            .sign_and_submit_then_watch(&signer.clone())
            .await
            .unwrap_err()
            .into()
    }
}

#[async_trait]
pub trait UtilFuncs {
    /// Gets the current height of the parachain
    async fn get_current_chain_height(&self) -> Result<u32, Error>;

    /// Get the address of the configured signer.
    fn get_account_id(&self) -> &AccountId;

    fn is_this_vault(&self, vault_id: &VaultId) -> bool;
}

#[async_trait]
impl UtilFuncs for InterBtcParachain {
    async fn get_current_chain_height(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().system().number(head).await?)
    }

    fn get_account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn is_this_vault(&self, vault_id: &VaultId) -> bool {
        &vault_id.account_id == self.get_account_id()
    }
}

#[async_trait]
pub trait CollateralBalancesPallet {
    async fn get_free_balance(&self, currency_id: CurrencyId) -> Result<Balance, Error>;

    async fn get_free_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, Error>;

    async fn get_reserved_balance(&self, currency_id: CurrencyId) -> Result<Balance, Error>;

    async fn get_reserved_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, Error>;

    async fn transfer_to(&self, recipient: &AccountId, amount: u128, currency_id: CurrencyId) -> Result<(), Error>;
}

#[async_trait]
impl CollateralBalancesPallet for InterBtcParachain {
    async fn get_free_balance(&self, currency_id: CurrencyId) -> Result<Balance, Error> {
        Ok(Self::get_free_balance_for_id(self, self.account_id.clone(), currency_id).await?)
    }

    async fn get_free_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .tokens()
            .accounts(id.clone(), currency_id, head)
            .await?
            .free)
    }

    async fn get_reserved_balance(&self, currency_id: CurrencyId) -> Result<Balance, Error> {
        Ok(Self::get_reserved_balance_for_id(self, self.account_id.clone(), currency_id).await?)
    }

    async fn get_reserved_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .tokens()
            .accounts(id.clone(), currency_id, head)
            .await?
            .reserved)
    }

    async fn transfer_to(&self, recipient: &AccountId, amount: u128, currency_id: CurrencyId) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .tokens()
                .transfer(recipient.clone(), currency_id, amount)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }
}

#[async_trait]
pub trait ReplacePallet {
    /// Request the replacement of a new vault ownership
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction
    /// * `amount` - amount of [Wrapped]
    /// * `griefing_collateral` - amount of griefing collateral
    async fn request_replace(&self, vault_id: &VaultId, amount: u128, griefing_collateral: u128) -> Result<(), Error>;

    /// Withdraw a request of vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the old vault
    /// * `amount` - the amount of [Wrapped] to replace
    async fn withdraw_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

    /// Accept request of vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - the initiator of the transaction: the new vault
    /// * `old_vault` - the vault to replace
    /// * `amount_btc` - the amount of [Wrapped] to replace
    /// * `collateral` - the collateral for replacement
    /// * `btc_address` - the address to send funds to
    async fn accept_replace(
        &self,
        new_vault: &VaultId,
        old_vault: &VaultId,
        amount_btc: u128,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error>;
    //
    /// Execute vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the old vault
    /// * `replace_id` - the ID of the replacement request
    /// * 'merkle_proof' - the merkle root of the block
    /// * `raw_tx` - the transaction id in bytes
    async fn execute_replace(&self, replace_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error>;

    /// Cancel vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the new vault
    /// * `replace_id` - the ID of the replacement request
    async fn cancel_replace(&self, replace_id: H256) -> Result<(), Error>;

    /// Get all replace requests accepted by the given vault
    async fn get_new_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcReplaceRequest)>, Error>;

    /// Get all replace requests made by the given vault
    async fn get_old_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcReplaceRequest)>, Error>;

    /// Get the time difference in number of blocks between when a replace
    /// request is created and required completion time by a vault
    async fn get_replace_period(&self) -> Result<u32, Error>;

    /// Get a replace request from storage
    async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, Error>;

    /// Gets the minimum btc amount for replace requests
    async fn get_replace_dust_amount(&self) -> Result<u128, Error>;
}

#[async_trait]
impl ReplacePallet for InterBtcParachain {
    async fn request_replace(&self, vault_id: &VaultId, amount: u128, griefing_collateral: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .request_replace(vault_id.currencies.clone(), amount, griefing_collateral)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn withdraw_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .withdraw_replace(vault_id.currencies.clone(), amount)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn accept_replace(
        &self,
        new_vault: &VaultId,
        old_vault: &VaultId,
        amount_btc: u128,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .accept_replace(
                    new_vault.currencies.clone(),
                    old_vault.clone(),
                    amount_btc,
                    collateral,
                    btc_address,
                )
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn execute_replace(&self, replace_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .execute_replace(replace_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_replace(&self, replace_id: H256) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .cancel_replace(replace_id)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Get all replace requests accepted by the given vault
    async fn get_new_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcReplaceRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc_client
            .request(
                "replace_getNewVaultReplaceRequests",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;
        join_all(
            result
                .into_iter()
                .map(|key| async move { self.get_replace_request(key).await.map(|value| (key, value)) }),
        )
        .await
        .into_iter()
        .collect()
    }

    /// Get all replace requests made by the given vault
    async fn get_old_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcReplaceRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc_client
            .request(
                "replace_getOldVaultReplaceRequests",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;
        join_all(
            result
                .into_iter()
                .map(|key| async move { self.get_replace_request(key).await.map(|value| (key, value)) }),
        )
        .await
        .into_iter()
        .collect()
    }

    async fn get_replace_period(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().replace().replace_period(head).await?)
    }

    async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .replace()
            .replace_requests(replace_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_replace_dust_amount(&self) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().replace().replace_btc_dust_value(head).await?)
    }
}

#[async_trait]
pub trait TimestampPallet {
    async fn get_time_now(&self) -> Result<u64, Error>;
}

#[async_trait]
impl TimestampPallet for InterBtcParachain {
    /// Get the current time as defined by the `timestamp` pallet.
    async fn get_time_now(&self) -> Result<u64, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().timestamp().now(head).await?)
    }
}

#[async_trait]
pub trait OraclePallet {
    async fn get_exchange_rate(&self, currency_id: CurrencyId) -> Result<FixedU128, Error>;

    async fn feed_values(&self, values: Vec<(OracleKey, FixedU128)>) -> Result<(), Error>;

    async fn set_bitcoin_fees(&self, value: FixedU128) -> Result<(), Error>;

    async fn get_bitcoin_fees(&self) -> Result<FixedU128, Error>;

    async fn wrapped_to_collateral(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error>;

    async fn collateral_to_wrapped(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error>;

    async fn has_updated(&self, key: &OracleKey) -> Result<bool, Error>;
}

#[async_trait]
impl OraclePallet for InterBtcParachain {
    /// Returns the last exchange rate in planck per satoshis, the time at which it was set
    /// and the configured max delay.
    async fn get_exchange_rate(&self, currency_id: CurrencyId) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .oracle()
            .aggregate(OracleKey::ExchangeRate(currency_id), head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    /// Sets the current exchange rate (i.e. DOT/BTC)
    ///
    /// # Arguments
    /// * `value` - the current exchange rate
    async fn feed_values(&self, values: Vec<(OracleKey, FixedU128)>) -> Result<(), Error> {
        let values = &values;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .oracle()
                .feed_values(values.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Sets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next block (~10 min)
    ///
    /// # Arguments
    /// * `value` - the estimated fee rate
    async fn set_bitcoin_fees(&self, value: FixedU128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .oracle()
                .feed_values(vec![(OracleKey::FeeEstimation, value)])
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Gets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next x blocks
    async fn get_bitcoin_fees(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .oracle()
            .aggregate(OracleKey::FeeEstimation, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    /// Converts the amount in btc to dot, based on the current set exchange rate.
    async fn wrapped_to_collateral(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "oracle_wrappedToCollateral",
                &[
                    to_json_value(BalanceWrapper { amount })?,
                    to_json_value(currency_id)?,
                    to_json_value(head)?,
                ],
            )
            .await?;

        Ok(result.amount)
    }

    /// Converts the amount in dot to btc, based on the current set exchange rate.
    async fn collateral_to_wrapped(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "oracle_collateralToWrapped",
                &[
                    to_json_value(BalanceWrapper { amount })?,
                    to_json_value(currency_id)?,
                    to_json_value(head)?,
                ],
            )
            .await?;

        Ok(result.amount)
    }

    async fn has_updated(&self, key: &OracleKey) -> Result<bool, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .oracle()
            .raw_values_updated(key.clone(), head)
            .await?
            .unwrap_or(false))
    }
}

#[async_trait]
pub trait RelayPallet {
    async fn report_vault_theft(&self, vault_id: &VaultId, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error>;

    async fn report_vault_double_payment(
        &self,
        vault_id: &VaultId,
        merkle_proofs: (Vec<u8>, Vec<u8>),
        raw_txs: (Vec<u8>, Vec<u8>),
    ) -> Result<(), Error>;

    async fn is_transaction_invalid(&self, vault_id: &VaultId, raw_tx: &[u8]) -> Result<bool, Error>;

    async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), Error>;

    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error>;

    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error>;
}

#[async_trait]
impl RelayPallet for InterBtcParachain {
    /// Submit extrinsic to report vault theft, consumer should
    /// first check `is_transaction_invalid` to ensure this call
    /// succeeds.
    ///
    /// # Arguments
    /// * `vault_id` - account id for the malicious vault
    /// * `merkle_proof` - merkle proof to verify inclusion
    /// * `raw_tx` - raw transaction
    async fn report_vault_theft(&self, vault_id: &VaultId, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .relay()
                .report_vault_theft(vault_id.clone(), merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Submit extrinsic to report that the vault made a duplicate payment (where each individually is valid)
    ///
    /// # Arguments
    /// * `vault_id` - account id for the malicious vault
    /// * `merkle_proofs` - merkle proof to verify inclusion
    /// * `raw_txs` - raw transaction
    async fn report_vault_double_payment(
        &self,
        vault_id: &VaultId,
        merkle_proofs: (Vec<u8>, Vec<u8>),
        raw_txs: (Vec<u8>, Vec<u8>),
    ) -> Result<(), Error> {
        let merkle_proofs = &merkle_proofs;
        let raw_txs = &raw_txs;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .relay()
                .report_vault_double_payment(vault_id.clone(), merkle_proofs.clone(), raw_txs.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Custom RPC that tests whether a Bitcoin transaction is invalid
    /// according to the following conditions:
    ///
    /// - The specified vault is a signer
    /// - The transaction is an invalid format
    /// - The transaction is not part of any ongoing request
    ///
    /// # Arguments
    /// * `vault_id` - vault account which features in vin
    /// * `raw_tx` - raw Bitcoin transaction
    async fn is_transaction_invalid(&self, vault_id: &VaultId, raw_tx: &[u8]) -> Result<bool, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(matches!(
            self.rpc_client
                .request(
                    "relay_isTransactionInvalid",
                    &[to_json_value(vault_id)?, to_json_value(raw_tx)?, to_json_value(head)?],
                )
                .await,
            Ok(()),
        ))
    }

    /// Initializes the relay with the provided block header and height,
    /// should be called automatically by relayer subject to the
    /// result of `is_initialized`.
    ///
    /// # Arguments
    /// * `header` - raw block header
    /// * `height` - starting height
    async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), Error> {
        let header = &header;
        // TODO: can we initialize the relay through the chain-spec?
        // we would also need to consider re-initialization per governance
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .relay()
                .initialize(header.clone(), height)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Stores a block header in the BTC-Relay.
    ///
    /// # Arguments
    /// * `header` - raw block header
    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        let header = &header;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .relay()
                .store_block_header(header.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Stores multiple block headers in the BTC-Relay.
    ///
    /// # Arguments
    /// * `headers` - raw block headers
    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error> {
        self.batch(
            headers
                .into_iter()
                .map(|raw_block_header| {
                    EncodedCall::Relay(metadata::runtime_types::relay::pallet::Call::store_block_header {
                        raw_block_header,
                    })
                })
                .collect(),
        )
        .await
    }
}

#[async_trait]
pub trait SecurityPallet {
    async fn get_parachain_status(&self) -> Result<StatusCode, Error>;

    async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error>;

    /// Gets the current active block number of the parachain
    async fn get_current_active_block_number(&self) -> Result<u32, Error>;
}

#[async_trait]
impl SecurityPallet for InterBtcParachain {
    /// Get the current security status of the parachain.
    /// Should be one of; `Running`, `Error` or `Shutdown`.
    async fn get_parachain_status(&self) -> Result<StatusCode, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().security().parachain_status(head).await?)
    }
    /// Return any `ErrorCode`s set in the security module.
    async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().security().errors(head).await?)
    }

    /// Gets the current active block number of the parachain
    async fn get_current_active_block_number(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().security().active_block_count(head).await?)
    }
}

#[async_trait]
pub trait IssuePallet {
    /// Request a new issue
    async fn request_issue(
        &self,
        amount: u128,
        vault_id: &VaultId,
        griefing_collateral: u128,
    ) -> Result<RequestIssueEvent, Error>;

    /// Execute a issue request by providing a Bitcoin transaction inclusion proof
    async fn execute_issue(&self, issue_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error>;

    /// Cancel an ongoing issue request
    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error>;

    async fn get_issue_request(&self, issue_id: H256) -> Result<InterBtcIssueRequest, Error>;

    async fn get_vault_issue_requests(&self, account_id: AccountId)
        -> Result<Vec<(H256, InterBtcIssueRequest)>, Error>;

    async fn get_issue_period(&self) -> Result<u32, Error>;

    async fn get_all_active_issues(&self) -> Result<Vec<(H256, InterBtcIssueRequest)>, Error>;
}

#[async_trait]
impl IssuePallet for InterBtcParachain {
    async fn request_issue(
        &self,
        amount: u128,
        vault_id: &VaultId,
        griefing_collateral: u128,
    ) -> Result<RequestIssueEvent, Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .issue()
                .request_issue(amount, vault_id.clone(), griefing_collateral)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?
        .find_first_event::<RequestIssueEvent>()?
        .ok_or(Error::RequestIssueIDNotFound)
    }

    async fn execute_issue(&self, issue_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .issue()
                .execute_issue(issue_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .issue()
                .cancel_issue(issue_id)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_issue_request(&self, issue_id: H256) -> Result<InterBtcIssueRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .issue()
            .issue_requests(issue_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_issue_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcIssueRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc_client
            .request(
                "issue_getVaultIssueRequests",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;
        join_all(
            result
                .into_iter()
                .map(|key| async move { self.get_issue_request(key).await.map(|value| (key, value)) }),
        )
        .await
        .into_iter()
        .collect()
        // Ok(result)
    }

    async fn get_issue_period(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().issue().issue_period(head).await?)
    }

    async fn get_all_active_issues(&self) -> Result<Vec<(H256, InterBtcIssueRequest)>, Error> {
        let current_height = self.get_current_chain_height().await?;
        let issue_period = self.get_issue_period().await?;

        let mut issue_requests = Vec::new();
        let head = self.get_latest_block_hash().await?;
        let mut iter = self.api.storage().issue().issue_requests_iter(head).await?;
        while let Some((issue_id, request)) = iter.next().await? {
            if request.status == IssueRequestStatus::Pending && request.opentime + issue_period > current_height {
                let key_hash = issue_id.0.as_slice();
                // last bytes are the raw key
                let key = &key_hash[key_hash.len() - 32..];
                issue_requests.push((H256::from_slice(key), request));
            }
        }
        Ok(issue_requests)
    }
}

#[async_trait]
pub trait RedeemPallet {
    /// Request a new redeem
    async fn request_redeem(&self, amount: u128, btc_address: BtcAddress, vault_id: &VaultId) -> Result<H256, Error>;

    /// Execute a redeem request by providing a Bitcoin transaction inclusion proof
    async fn execute_redeem(&self, redeem_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error>;

    /// Cancel an ongoing redeem request
    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error>;

    async fn get_redeem_request(&self, redeem_id: H256) -> Result<InterBtcRedeemRequest, Error>;

    /// Get all open redeem requests requested of the given vault
    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRedeemRequest)>, Error>;

    async fn get_redeem_period(&self) -> Result<BlockNumber, Error>;
}

#[async_trait]
impl RedeemPallet for InterBtcParachain {
    async fn request_redeem(&self, amount: u128, btc_address: BtcAddress, vault_id: &VaultId) -> Result<H256, Error> {
        let redeem_event = self
            .with_unique_signer(|signer| async move {
                self.api
                    .tx()
                    .redeem()
                    .request_redeem(amount, btc_address, vault_id.clone())
                    .sign_and_submit_then_watch(&signer)
                    .await
            })
            .await?
            .find_first_event::<RequestRedeemEvent>()?
            .ok_or(Error::RequestRedeemIDNotFound)?;
        Ok(redeem_event.redeem_id)
    }

    async fn execute_redeem(&self, redeem_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .redeem()
                .execute_redeem(redeem_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .redeem()
                .cancel_redeem(redeem_id, reimburse)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_redeem_request(&self, redeem_id: H256) -> Result<InterBtcRedeemRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .redeem()
            .redeem_requests(redeem_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRedeemRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc_client
            .request(
                "redeem_getVaultRedeemRequests",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;
        join_all(
            result
                .into_iter()
                .map(|key| async move { self.get_redeem_request(key).await.map(|value| (key, value)) }),
        )
        .await
        .into_iter()
        .collect()
    }

    async fn get_redeem_period(&self) -> Result<BlockNumber, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().redeem().redeem_period(head).await?)
    }
}

#[async_trait]
pub trait RefundPallet {
    /// Execute a refund request by providing a Bitcoin transaction inclusion proof
    async fn execute_refund(&self, refund_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error>;

    /// Fetch a refund request from storage
    async fn get_refund_request(&self, refund_id: H256) -> Result<InterBtcRefundRequest, Error>;

    /// Get all open refund requests requested of the given vault
    async fn get_vault_refund_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRefundRequest)>, Error>;
}

#[async_trait]
impl RefundPallet for InterBtcParachain {
    async fn execute_refund(&self, refund_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .refund()
                .execute_refund(refund_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_refund_request(&self, refund_id: H256) -> Result<InterBtcRefundRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .refund()
            .refund_requests(refund_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_refund_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRefundRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc_client
            .request(
                "refund_getVaultRefundRequests",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;
        join_all(
            result
                .into_iter()
                .map(|key| async move { self.get_refund_request(key).await.map(|value| (key, value)) }),
        )
        .await
        .into_iter()
        .collect()
    }
}

const BLOCK_WAIT_TIMEOUT: u64 = 6;

#[async_trait]
pub trait BtcRelayPallet {
    async fn get_best_block(&self) -> Result<H256Le, Error>;

    async fn get_best_block_height(&self) -> Result<u32, Error>;

    async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error>;

    async fn get_block_header(&self, hash: H256Le) -> Result<InterBtcRichBlockHeader, Error>;

    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error>;

    async fn get_parachain_confirmations(&self) -> Result<BlockNumber, Error>;

    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        _btc_confirmations: Option<BlockNumber>, // todo: can we remove this?
    ) -> Result<(), Error>;

    async fn verify_block_header_inclusion(&self, block_hash: H256Le) -> Result<(), Error>;
}

#[async_trait]
impl BtcRelayPallet for InterBtcParachain {
    /// Get the hash of the current best tip.
    async fn get_best_block(&self) -> Result<H256Le, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().btc_relay().best_block(head).await?)
    }

    /// Get the current best known height.
    async fn get_best_block_height(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().btc_relay().best_block_height(head).await?)
    }

    /// Get the block hash for the main chain at the specified height.
    ///
    /// # Arguments
    /// * `height` - chain height
    async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().btc_relay().chains_hashes(0, height, head).await?)
    }

    /// Get the corresponding block header for the given hash.
    ///
    /// # Arguments
    /// * `hash` - little endian block hash
    async fn get_block_header(&self, hash: H256Le) -> Result<InterBtcRichBlockHeader, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().btc_relay().block_headers(hash, head).await?)
    }

    /// Get the global security parameter k for stable Bitcoin transactions
    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .btc_relay()
            .stable_bitcoin_confirmations(head)
            .await?)
    }

    /// Get the global security parameter for stable parachain confirmations
    async fn get_parachain_confirmations(&self) -> Result<BlockNumber, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .btc_relay()
            .stable_parachain_confirmations(head)
            .await?)
    }

    /// Wait until Bitcoin block is submitted to the relay
    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        _btc_confirmations: Option<BlockNumber>,
    ) -> Result<(), Error> {
        loop {
            match self.verify_block_header_inclusion(block_hash.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) if e.is_invalid_chain_id() => return Err(e),
                _ => {
                    log::trace!(
                        "block {} not found or confirmed, waiting for {} seconds",
                        Into::<RichH256Le>::into(block_hash.clone()),
                        BLOCK_WAIT_TIMEOUT
                    );
                    sleep(Duration::from_secs(BLOCK_WAIT_TIMEOUT)).await;
                }
            };
        }
    }

    /// check that the block with the given block is included in the main chain of the relay, with sufficient
    /// confirmations
    async fn verify_block_header_inclusion(&self, block_hash: H256Le) -> Result<(), Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Result<(), DispatchError> = self
            .rpc_client
            .request(
                "btcRelay_verifyBlockHeaderInclusion",
                &[
                    to_json_value(Into::<RichH256Le>::into(block_hash))?,
                    to_json_value(head)?,
                ],
            )
            .await?;

        result.map_err(|err| Error::SubxtRuntimeError(SubxtError::Runtime(subxt::RuntimeError(err))))
    }
}

#[async_trait]
pub trait VaultRegistryPallet {
    async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, Error>;

    async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, Error>;

    async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, Error>;

    async fn register_vault(&self, vault_id: &VaultId, collateral: u128, public_key: BtcPublicKey)
        -> Result<(), Error>;

    async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

    async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

    async fn update_public_key(&self, vault_id: &VaultId, public_key: BtcPublicKey) -> Result<(), Error>;

    async fn register_address(&self, vault_id: &VaultId, btc_address: BtcAddress) -> Result<(), Error>;

    async fn get_required_collateral_for_wrapped(
        &self,
        amount_btc: u128,
        collateral_currency: CurrencyId,
    ) -> Result<u128, Error>;

    async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, Error>;

    async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, Error>;
}

#[async_trait]
impl VaultRegistryPallet for InterBtcParachain {
    /// Fetch a specific vault by ID.
    ///
    /// # Arguments
    /// * `vault_id` - account ID of the vault
    ///
    /// # Errors
    /// * `VaultNotFound` - if the rpc returned a default value rather than the vault we want
    /// * `VaultLiquidated` - if the vault is liquidated
    /// * `VaultCommittedTheft` - if the vault is stole BTC
    async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, Error> {
        let head = self.get_latest_block_hash().await?;
        match self
            .api
            .storage()
            .vault_registry()
            .vaults(vault_id.clone(), head)
            .await?
        {
            Some(InterBtcVault {
                status: VaultStatus::Liquidated,
                ..
            }) => Err(Error::VaultLiquidated),
            Some(InterBtcVault {
                status: VaultStatus::CommittedTheft,
                ..
            }) => Err(Error::VaultCommittedTheft),
            Some(vault) if &vault.id == vault_id => Ok(vault),
            _ => Err(Error::VaultNotFound),
        }
    }

    async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result = self
            .rpc_client
            .request(
                "vaultRegistry_getVaultsByAccountId",
                &[to_json_value(account_id)?, to_json_value(head)?],
            )
            .await?;

        Ok(result)
    }

    /// Fetch all active vaults.
    async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, Error> {
        let mut vaults = Vec::new();
        let head = self.get_latest_block_hash().await?;
        let mut iter = self.api.storage().vault_registry().vaults_iter(head).await?;
        while let Some((_, account)) = iter.next().await? {
            if let VaultStatus::Active(..) = account.status {
                vaults.push(account);
            }
        }
        Ok(vaults)
    }

    /// Submit extrinsic to register a vault.
    ///
    /// # Arguments
    /// * `collateral` - deposit
    /// * `public_key` - Bitcoin public key
    async fn register_vault(
        &self,
        vault_id: &VaultId,
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), Error> {
        let public_key = &public_key.clone();
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .register_vault(vault_id.currencies.clone(), collateral, public_key.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Locks additional collateral as a security against stealing the
    /// Bitcoin locked with it.
    ///
    /// # Arguments
    /// * `amount` - the amount of extra collateral to lock
    async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .deposit_collateral(vault_id.currencies.clone(), amount)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Withdraws `amount` of the collateral from the amount locked by
    /// the vault corresponding to the origin account
    /// The collateral left after withdrawal must be more than MinimumCollateralVault
    /// and above the SecureCollateralThreshold. Collateral that is currently
    /// being used to back issued tokens remains locked until the Vault
    /// is used for a redeem request (full release can take multiple redeem requests).
    ///
    /// # Arguments
    /// * `amount` - the amount of collateral to withdraw
    async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .withdraw_collateral(vault_id.currencies.clone(), amount)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Update the default BTC public key for the vault corresponding to the signer.
    ///
    /// # Arguments
    /// * `public_key` - the new public key of the vault
    async fn update_public_key(&self, vault_id: &VaultId, public_key: BtcPublicKey) -> Result<(), Error> {
        let public_key = &public_key.clone();
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .update_public_key(vault_id.currencies.clone(), public_key.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Register a new BTC address, useful for change addresses.
    ///
    /// # Arguments
    /// * `btc_address` - the new btc address of the vault
    async fn register_address(&self, vault_id: &VaultId, btc_address: BtcAddress) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .register_address(vault_id.currencies.clone(), btc_address)
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Custom RPC that calculates the exact collateral required to cover the BTC amount.
    ///
    /// # Arguments
    /// * `amount_btc` - amount of btc to cover
    async fn get_required_collateral_for_wrapped(
        &self,
        amount_btc: u128,
        collateral_currency: CurrencyId,
    ) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "vaultRegistry_getRequiredCollateralForWrapped",
                &[
                    to_json_value(BalanceWrapper { amount: amount_btc })?,
                    to_json_value(collateral_currency)?,
                    to_json_value(head)?,
                ],
            )
            .await?;

        Ok(result.amount)
    }

    /// Get the amount of collateral required for the given vault to be at the
    /// current SecureCollateralThreshold with the current exchange rate
    async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "vaultRegistry_getRequiredCollateralForVault",
                &[to_json_value(vault_id)?, to_json_value(head)?],
            )
            .await?;

        Ok(result.amount)
    }

    async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "vaultRegistry_getVaultTotalCollateral",
                &[to_json_value(vault_id)?, to_json_value(head)?],
            )
            .await?;

        Ok(result.amount)
    }
}

#[async_trait]
pub trait FeePallet {
    async fn get_issue_griefing_collateral(&self) -> Result<FixedU128, Error>;
    async fn get_issue_fee(&self) -> Result<FixedU128, Error>;
    async fn get_replace_griefing_collateral(&self) -> Result<FixedU128, Error>;
}

#[async_trait]
impl FeePallet for InterBtcParachain {
    async fn get_issue_griefing_collateral(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().fee().issue_griefing_collateral(head).await?)
    }

    async fn get_issue_fee(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().fee().issue_fee(head).await?)
    }

    async fn get_replace_griefing_collateral(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().fee().replace_griefing_collateral(head).await?)
    }
}

#[async_trait]
pub trait SudoPallet {
    async fn sudo(&self, call: EncodedCall) -> Result<(), Error>;
    async fn set_storage<V: Encode + Send + Sync>(&self, module: &str, key: &str, value: V) -> Result<(), Error>;
    async fn set_redeem_period(&self, period: BlockNumber) -> Result<(), Error>;
    async fn set_parachain_confirmations(&self, value: BlockNumber) -> Result<(), Error>;
    async fn set_bitcoin_confirmations(&self, value: u32) -> Result<(), Error>;
    async fn set_issue_period(&self, period: u32) -> Result<(), Error>;
    async fn insert_authorized_oracle(&self, account_id: AccountId, name: String) -> Result<(), Error>;
    async fn set_replace_period(&self, period: u32) -> Result<(), Error>;
}

#[cfg(any(feature = "standalone-metadata", feature = "parachain-metadata-testnet"))]
#[async_trait]
impl SudoPallet for InterBtcParachain {
    async fn sudo(&self, call: EncodedCall) -> Result<(), Error> {
        let call = &call;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .sudo()
                .sudo(call.clone())
                .sign_and_submit_then_watch(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn set_storage<V: Encode + Send + Sync>(&self, module: &str, key: &str, value: V) -> Result<(), Error> {
        let module = subxt::sp_core::twox_128(module.as_bytes());
        let item = subxt::sp_core::twox_128(key.as_bytes());

        Ok(self
            .sudo(EncodedCall::System(
                metadata::runtime_types::frame_system::pallet::Call::set_storage {
                    items: vec![([module, item].concat(), value.encode())],
                },
            ))
            .await?)
    }

    async fn set_redeem_period(&self, period: BlockNumber) -> Result<(), Error> {
        Ok(self
            .sudo(EncodedCall::Redeem(
                metadata::runtime_types::redeem::pallet::Call::set_redeem_period { period },
            ))
            .await?)
    }

    /// Set the global security parameter for stable parachain confirmations
    async fn set_parachain_confirmations(&self, value: BlockNumber) -> Result<(), Error> {
        self.set_storage(BTC_RELAY_MODULE, STABLE_PARACHAIN_CONFIRMATIONS, value)
            .await
    }

    /// Set the global security parameter k for stable Bitcoin transactions
    async fn set_bitcoin_confirmations(&self, value: u32) -> Result<(), Error> {
        self.set_storage(BTC_RELAY_MODULE, STABLE_BITCOIN_CONFIRMATIONS, value)
            .await
    }

    async fn set_issue_period(&self, period: u32) -> Result<(), Error> {
        Ok(self
            .sudo(EncodedCall::Issue(
                metadata::runtime_types::issue::pallet::Call::set_issue_period { period },
            ))
            .await?)
    }

    /// Adds a new authorized oracle with the given name and the signer's AccountId
    ///
    /// # Arguments
    /// * `account_id` - The Account ID of the new oracle
    /// * `name` - The name of the new oracle
    async fn insert_authorized_oracle(&self, account_id: AccountId, name: String) -> Result<(), Error> {
        Ok(self
            .sudo(EncodedCall::Oracle(
                metadata::runtime_types::oracle::pallet::Call::insert_authorized_oracle {
                    account_id,
                    name: name.into_bytes(),
                },
            ))
            .await?)
    }

    async fn set_replace_period(&self, period: u32) -> Result<(), Error> {
        Ok(self
            .sudo(EncodedCall::Replace(
                metadata::runtime_types::replace::pallet::Call::set_replace_period { period },
            ))
            .await?)
    }
}
