pub use module_exchange_rate_oracle::BtcTxFeesPerByte;

use async_trait::async_trait;
use core::marker::PhantomData;
use futures::{stream::StreamExt, FutureExt, SinkExt};
use jsonrpsee_types::{
    error::Error as RequestError,
    jsonrpc::{to_value as to_json_value, Error as JsonRpcError, ErrorCode as JsonRpcErrorCode, Params},
};
use module_exchange_rate_oracle_rpc_runtime_api::BalanceWrapper;
use sp_arithmetic::FixedU128;
use sp_core::H256;
use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};
use substrate_subxt::{
    sudo::*, Call, Client as SubxtClient, ClientBuilder as SubxtClientBuilder, Error as SubxtError, Event,
    EventSubscription, EventTypeRegistry, EventsDecoder, RpcClient, Signer,
};
use tokio::{sync::RwLock, time::delay_for};

use crate::{
    balances_dot::*, btc_relay::*, conn::*, error::POOL_INVALID_TX, exchange_rate_oracle::*, fee::*, issue::*,
    pallets::*, redeem::*, refund::*, replace::*, security::*, staked_relayers::*, timestamp::*, types::*, utility::*,
    vault_registry::*, AccountId, BlockNumber, Error, PolkaBtcRuntime,
};

#[derive(Clone)]
pub struct PolkaBtcProvider {
    rpc_client: RpcClient,
    ext_client: SubxtClient<PolkaBtcRuntime>,
    signer: Arc<RwLock<PolkaBtcSigner>>,
    account_id: AccountId,
}

impl PolkaBtcProvider {
    pub async fn new<P: Into<RpcClient>>(rpc_client: P, signer: PolkaBtcSigner) -> Result<Self, Error> {
        let account_id = signer.account_id().clone();
        let rpc_client = rpc_client.into();
        let ext_client = SubxtClientBuilder::<PolkaBtcRuntime>::new()
            .set_client(rpc_client.clone())
            .build()
            .await?;

        let provider = Self {
            rpc_client,
            ext_client,
            signer: Arc::new(RwLock::new(signer)),
            account_id,
        };
        provider.refresh_nonce().await?;
        Ok(provider)
    }

    pub async fn from_url(url: &str, signer: PolkaBtcSigner) -> Result<Self, Error> {
        let ws_config = new_websocket_config(url, None, None)?;
        let ws_client = new_websocket_client(ws_config).await?;
        Self::new(ws_client, signer).await
    }

    pub async fn from_url_with_retry(
        url: &str,
        signer: PolkaBtcSigner,
        connection_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::from_url_and_config_with_retry(url, signer, None, None, connection_timeout).await
    }

    pub async fn from_url_and_config_with_retry(
        url: &str,
        signer: PolkaBtcSigner,
        max_concurrent_requests: Option<usize>,
        max_notifs_per_subscription: Option<usize>,
        connection_timeout: Duration,
    ) -> Result<Self, Error> {
        let ws_config = new_websocket_config(url, max_concurrent_requests, max_notifs_per_subscription)?;
        let ws_client = new_websocket_client_with_retry(ws_config, connection_timeout).await?;
        Self::new(ws_client, signer).await
    }

    async fn refresh_nonce(&self) -> Result<(), Error> {
        let mut signer = self.signer.write().await;
        // For getting the nonce, use latest, possibly non-finalized block.
        // TODO: we might want to wait until the latest block is actually finalized
        // query account info in order to get the nonce value used for communication
        let account_info = crate::frame_system::AccountStoreExt::account(
            &self.ext_client,
            self.account_id.clone(),
            Option::<H256>::None,
        )
        .await?;
        log::info!("Refreshing nonce to {}", account_info.nonce);
        signer.set_nonce(account_info.nonce);
        Ok(())
    }

    /// Gets a copy of the signer with a unique nonce
    async fn with_unique_signer<F, R, T>(&self, call: F) -> Result<T, Error>
    where
        F: FnOnce(PolkaBtcSigner) -> R,
        R: Future<Output = Result<T, SubxtError>>,
    {
        let signer = {
            let mut signer = self.signer.write().await;
            // return the current value, increment afterwards
            let cloned_signer = signer.clone();
            signer.increment_nonce();
            cloned_signer
        };
        match call(signer).await {
            Ok(val) => Ok(val),
            Err(SubxtError::Rpc(RequestError::Request(JsonRpcError {
                code: JsonRpcErrorCode::MethodError(POOL_INVALID_TX),
                message,
                ..
            }))) => {
                // without parsing the error message there is no way
                // to know why the transaction is invalid, so always
                // refresh nonce and propogate message to caller
                self.refresh_nonce().await?;
                Err(Error::InvalidTransaction(message))
            }
            Err(err) => Err(err.into()),
        }
    }

    pub async fn get_latest_block_hash(&self) -> Result<Option<H256>, Error> {
        Ok(Some(self.ext_client.finalized_head().await?))
    }

    pub async fn get_latest_block(&self) -> Result<Option<PolkaBtcBlock>, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.block::<H256>(head).await?)
    }

    /// Subscribe to new parachain blocks.
    pub async fn on_block<F, R>(&self, on_block: F) -> Result<(), Error>
    where
        F: Fn(PolkaBtcHeader) -> R,
        R: Future<Output = Result<(), Error>>,
    {
        let mut sub = self.ext_client.subscribe_finalized_blocks().await?;
        loop {
            on_block(sub.next().await.ok_or(Error::ChannelClosed)?).await?;
        }
    }

    /// Subscription service that should listen forever, only returns if the initial subscription
    /// cannot be established. Calls `on_error` when an error event has been received, or when an
    /// event has been received that failed to be decoded into a raw event.
    ///
    /// # Arguments
    /// * `on_error` - callback for decoding errors, is not allowed to take too long
    pub async fn on_event_error<E: Fn(SubxtError)>(&self, on_error: E) -> Result<(), Error> {
        let sub = self.ext_client.subscribe_finalized_events().await?;
        let decoder =
            EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone(), EventTypeRegistry::new());

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, &decoder);
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
        T: Event<PolkaBtcRuntime> + core::fmt::Debug,
        F: FnMut(T) -> R,
        R: Future<Output = ()>,
        E: Fn(SubxtError),
    {
        let sub = self.ext_client.subscribe_finalized_events().await?;
        let decoder =
            EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone(), EventTypeRegistry::new());

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, &decoder);
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

    async fn sudo<C: Call<PolkaBtcRuntime>>(&self, call: C) -> Result<(), Error> {
        let encoded_call = self.ext_client.encode(call)?;
        self.with_unique_signer(|signer| async move { self.ext_client.sudo_and_watch(&signer, &encoded_call).await })
            .await?;
        Ok(())
    }

    async fn batch<C: Call<PolkaBtcRuntime>>(&self, calls: Vec<C>) -> Result<(), Error> {
        let encoded_calls = calls
            .into_iter()
            .map(|call| self.ext_client.encode(call))
            .collect::<Result<Vec<_>, _>>()?;
        self.with_unique_signer(|signer| async move { self.ext_client.batch_and_watch(&signer, encoded_calls).await })
            .await?;
        Ok(())
    }
}

#[async_trait]
pub trait UtilFuncs {
    /// Gets the current height of the parachain
    async fn get_current_chain_height(&self) -> Result<u32, Error>;

    async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, Error>;

    /// Get the address of the configured signer.
    fn get_account_id(&self) -> &AccountId;
}

#[async_trait]
impl UtilFuncs for PolkaBtcProvider {
    async fn get_current_chain_height(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        let query_result = self.ext_client.block(head).await?;
        match query_result {
            Some(x) => Ok(x.block.header.number),
            None => Err(Error::BlockNotFound),
        }
    }

    async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, Error> {
        let hash = self.ext_client.block_hash(Some(parachain_height.into())).await?;
        Ok(self.ext_client.best_block_height(hash).await?)
    }

    fn get_account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[async_trait]
pub trait DotBalancesPallet {
    async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn get_free_dot_balance_for_id(&self, id: AccountId) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), Error>;
}

#[async_trait]
impl DotBalancesPallet for PolkaBtcProvider {
    async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        Ok(Self::get_free_dot_balance_for_id(&self, self.account_id.clone()).await?)
    }

    async fn get_free_dot_balance_for_id(&self, id: AccountId) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.account(id.clone(), head).await?.free)
    }

    async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.account(self.account_id.clone(), head).await?.reserved)
    }

    async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.transfer_and_watch(&signer, &destination, amount).await
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
    /// * `amount` - amount of PolkaBTC
    /// * `griefing_collateral` - amount of DOT
    async fn request_replace(&self, amount: u128, griefing_collateral: u128) -> Result<H256, Error>;

    /// Withdraw a request of vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the old vault
    /// * `replace_id` - the unique identifier of the replace request
    async fn withdraw_replace(&self, replace_id: H256) -> Result<(), Error>;

    /// Accept request of vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - the initiator of the transaction: the new vault
    /// * `replace_id` - the unique identifier for the specific request
    /// * `collateral` - the collateral for replacement
    /// * `btc_address` - the address to send funds to
    async fn accept_replace(&self, replace_id: H256, collateral: u128, btc_address: BtcAddress) -> Result<(), Error>;

    /// Auction forces vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the new vault
    /// * `old_vault` - the old vault of the replacement request
    /// * `btc_amount` - the btc amount to be transferred over from old to new
    /// * `collateral` - the collateral to be transferred over from old to new
    /// * `btc_address` - the address to send funds to
    async fn auction_replace(
        &self,
        old_vault: AccountId,
        btc_amount: u128,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error>;

    /// Execute vault replacement
    ///
    /// # Arguments
    ///
    /// * `&self` - sender of the transaction: the old vault
    /// * `replace_id` - the ID of the replacement request
    /// * `tx_id` - the backing chain transaction id
    /// * 'merkle_proof' - the merkle root of the block
    /// * `raw_tx` - the transaction id in bytes
    async fn execute_replace(
        &self,
        replace_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

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
    ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, Error>;

    /// Get all replace requests made by the given vault
    async fn get_old_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, Error>;

    /// Get the time difference in number of blocks between when a replace
    /// request is created and required completion time by a vault
    async fn get_replace_period(&self) -> Result<u32, Error>;

    /// Set the time difference in number of blocks between when a replace
    /// request is created and required completion time by a vault
    async fn set_replace_period(&self, period: u32) -> Result<(), Error>;

    /// Get a replace request from storage
    async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, Error>;

    /// Gets the minimum btc amount for replace requests/auctions
    async fn get_replace_dust_amount(&self) -> Result<u128, Error>;
}

#[async_trait]
impl ReplacePallet for PolkaBtcProvider {
    async fn request_replace(&self, amount: u128, griefing_collateral: u128) -> Result<H256, Error> {
        let result = self
            .with_unique_signer(|signer| async move {
                self.ext_client
                    .request_replace_and_watch(&signer, amount, griefing_collateral)
                    .await
            })
            .await?;

        if let Some(event) = result.request_replace()? {
            Ok(event.replace_id)
        } else {
            Err(Error::RequestReplaceIDNotFound)
        }
    }

    async fn withdraw_replace(&self, replace_id: H256) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.withdraw_replace_and_watch(&signer, replace_id).await
        })
        .await?;
        Ok(())
    }

    async fn accept_replace(&self, replace_id: H256, collateral: u128, btc_address: BtcAddress) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .accept_replace_and_watch(&signer, replace_id, collateral, btc_address)
                .await
        })
        .await?;
        Ok(())
    }

    async fn auction_replace(
        &self,
        old_vault: AccountId,
        btc_amount: u128,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .auction_replace_and_watch(&signer, old_vault, btc_amount, collateral, btc_address)
                .await
        })
        .await?;
        Ok(())
    }

    async fn execute_replace(
        &self,
        replace_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .execute_replace_and_watch(&signer, replace_id, tx_id, merkle_proof, raw_tx)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_replace(&self, replace_id: H256) -> Result<(), Error> {
        self.with_unique_signer(
            |signer| async move { self.ext_client.cancel_replace_and_watch(&signer, replace_id).await },
        )
        .await?;
        Ok(())
    }

    /// Get all replace requests accepted by the given vault
    async fn get_new_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, Error> {
        let result: Vec<(H256, PolkaBtcReplaceRequest)> = self
            .rpc_client
            .request(
                "replace_getNewVaultReplaceRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(result)
    }

    /// Get all replace requests made by the given vault
    async fn get_old_vault_replace_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcReplaceRequest)>, Error> {
        let result: Vec<(H256, PolkaBtcReplaceRequest)> = self
            .rpc_client
            .request(
                "replace_getOldVaultReplaceRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(result)
    }

    async fn get_replace_period(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.replace_period(head).await?)
    }

    async fn set_replace_period(&self, period: u32) -> Result<(), Error> {
        Ok(self
            .sudo(SetReplacePeriodCall {
                period,
                _runtime: PhantomData {},
            })
            .await?)
    }

    async fn get_replace_request(&self, replace_id: H256) -> Result<PolkaBtcReplaceRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.replace_requests(replace_id, head).await?)
    }

    async fn get_replace_dust_amount(&self) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.replace_btc_dust_value(head).await?)
    }
}

#[async_trait]
pub trait TimestampPallet {
    async fn get_time_now(&self) -> Result<u64, Error>;
}

#[async_trait]
impl TimestampPallet for PolkaBtcProvider {
    /// Get the current time as defined by the `timestamp` pallet.
    async fn get_time_now(&self) -> Result<u64, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.now(head).await?)
    }
}

#[async_trait]
pub trait ExchangeRateOraclePallet {
    async fn get_exchange_rate_info(&self) -> Result<(FixedU128, u64, u64), Error>;

    async fn set_exchange_rate_info(&self, dot_per_btc: FixedU128) -> Result<(), Error>;

    async fn insert_authorized_oracle(&self, account_id: AccountId, name: String) -> Result<(), Error>;

    async fn set_btc_tx_fees_per_byte(&self, fast: u32, half: u32, hour: u32) -> Result<(), Error>;

    async fn get_btc_tx_fees_per_byte(&self) -> Result<BtcTxFeesPerByte, Error>;

    async fn btc_to_dots(&self, amount: u128) -> Result<u128, Error>;

    async fn dots_to_btc(&self, amount: u128) -> Result<u128, Error>;
}

#[async_trait]
impl ExchangeRateOraclePallet for PolkaBtcProvider {
    /// Returns the last exchange rate in planck per satoshis, the time at which it was set
    /// and the configured max delay.
    async fn get_exchange_rate_info(&self) -> Result<(FixedU128, u64, u64), Error> {
        let head = self.get_latest_block_hash().await?;
        let get_rate = self.ext_client.exchange_rate(head);
        let get_time = self.ext_client.last_exchange_rate_time(head);
        let get_delay = self.ext_client.max_delay(head);

        match tokio::try_join!(get_rate, get_time, get_delay) {
            Ok((rate, time, delay)) => Ok((rate, time, delay)),
            Err(_) => Err(Error::ExchangeRateInfo),
        }
    }

    /// Sets the current exchange rate as BTC/DOT
    ///
    /// # Arguments
    /// * `dot_per_btc` - the current dot per btc exchange rate
    async fn set_exchange_rate_info(&self, dot_per_btc: FixedU128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.set_exchange_rate_and_watch(&signer, dot_per_btc).await
        })
        .await?;
        Ok(())
    }

    /// Adds a new authorized oracle with the given name and the signer's AccountId
    ///
    /// # Arguments
    /// * `account_id` - The Account ID of the new oracle
    /// * `name` - The name of the new oracle
    async fn insert_authorized_oracle(&self, account_id: AccountId, name: String) -> Result<(), Error> {
        Ok(self
            .sudo(InsertAuthorizedOracleCall {
                account_id,
                name: name.into_bytes(),
                _runtime: PhantomData {},
            })
            .await?)
    }

    /// Sets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next x blocks
    ///
    /// # Arguments
    /// * `fast` - The estimated Satoshis per bytes to get included in the next block (~10 min)
    /// * `half` - The estimated Satoshis per bytes to get included in the next 3 blocks (~half hour)
    /// * `hour` - The estimated Satoshis per bytes to get included in the next 6 blocks (~hour)
    async fn set_btc_tx_fees_per_byte(&self, fast: u32, half: u32, hour: u32) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .set_btc_tx_fees_per_byte_and_watch(&signer, fast, half, hour)
                .await
        })
        .await?;
        Ok(())
    }

    /// Gets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next x blocks
    async fn get_btc_tx_fees_per_byte(&self) -> Result<BtcTxFeesPerByte, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.satoshi_per_bytes(head).await?)
    }

    /// Converts the amount in btc to dot, based on the current set exchange rate.
    async fn btc_to_dots(&self, amount_btc: u128) -> Result<u128, Error> {
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "exchangeRateOracle_btcToDots",
                Params::Array(vec![to_json_value(BalanceWrapper { amount: amount_btc })?]),
            )
            .await?;

        Ok(result.amount)
    }

    /// Converts the amount in dot to btc, based on the current set exchange rate.
    async fn dots_to_btc(&self, amount_dot: u128) -> Result<u128, Error> {
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "exchangeRateOracle_dotsToBtc",
                Params::Array(vec![to_json_value(BalanceWrapper { amount: amount_dot })?]),
            )
            .await?;

        Ok(result.amount)
    }
}

#[async_trait]
pub trait StakedRelayerPallet {
    async fn get_active_stake(&self) -> Result<u128, Error>;

    async fn get_active_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error>;

    async fn get_inactive_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error>;

    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error>;

    async fn deregister_staked_relayer(&self) -> Result<(), Error>;

    async fn suggest_status_update(
        &self,
        deposit: u128,
        status_code: StatusCode,
        add_error: Option<ErrorCode>,
        remove_error: Option<ErrorCode>,
        block_hash: Option<H256Le>,
        message: String,
    ) -> Result<(), Error>;

    async fn vote_on_status_update(&self, status_update_id: u64, approve: bool) -> Result<(), Error>;

    async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, Error>;

    async fn report_vault_theft(
        &self,
        vault_id: AccountId,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    async fn is_transaction_invalid(&self, vault_id: AccountId, raw_tx: Vec<u8>) -> Result<bool, Error>;

    async fn set_maturity_period(&self, period: u32) -> Result<(), Error>;

    async fn evaluate_status_update(&self, status_update_id: u64) -> Result<(), Error>;

    async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), Error>;

    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error>;

    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error>;
}

#[async_trait]
impl StakedRelayerPallet for PolkaBtcProvider {
    /// Get the stake registered for this staked relayer.
    async fn get_active_stake(&self) -> Result<u128, Error> {
        Ok(self.get_active_stake_by_id(self.account_id.clone()).await?)
    }

    /// Get the stake registered for this staked relayer.
    async fn get_active_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.active_staked_relayers(&account_id, head).await?.stake)
    }

    /// Get the stake registered for this inactive staked relayer.
    async fn get_inactive_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.inactive_staked_relayers(&account_id, head).await?.stake)
    }

    /// Submit extrinsic to register the staked relayer.
    ///
    /// # Arguments
    /// * `stake` - deposit
    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.register_staked_relayer_and_watch(&signer, stake).await
        })
        .await?;
        Ok(())
    }

    /// Submit extrinsic to deregister the staked relayer.
    async fn deregister_staked_relayer(&self) -> Result<(), Error> {
        self.with_unique_signer(
            |signer| async move { self.ext_client.deregister_staked_relayer_and_watch(&signer).await },
        )
        .await?;
        Ok(())
    }

    /// Submit extrinsic to suggest a new status update. There are
    /// four possible error codes as defined in the specification:
    ///
    /// * `NoDataBTCRelay` - missing transactional data for a block header
    /// * `InvalidBTCRelay` - invalid transaction was detected in a block header
    /// * `OracleOffline` - oracle liveness failure
    /// * `Liquidation` - at least one vault is being liquidated
    ///
    /// Currently only `NoDataBTCRelay` can be voted upon.
    ///
    /// # Arguments
    /// * `deposit` - collateral held while ballot underway
    /// * `status_code` - one of `Running`, `Error`, `Shutdown`
    /// * `add_error` - error to add to `BTreeSet<ErrorCode>`
    /// * `remove_error` - error to remove from `BTreeSet<ErrorCode>`
    /// * `block_hash` - optional block hash for btc-relay reports
    async fn suggest_status_update(
        &self,
        deposit: u128,
        status_code: StatusCode,
        add_error: Option<ErrorCode>,
        remove_error: Option<ErrorCode>,
        block_hash: Option<H256Le>,
        message: String,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .suggest_status_update_and_watch(
                    &signer,
                    deposit,
                    status_code,
                    add_error,
                    remove_error,
                    block_hash,
                    message.into_bytes(),
                )
                .await
        })
        .await?;
        Ok(())
    }

    /// Vote on an ongoing proposal by ID.
    ///
    /// # Arguments
    /// * `status_update_id` - ID of the status update
    /// * `approve` - whether to approve or reject the proposal
    async fn vote_on_status_update(&self, status_update_id: u64, approve: bool) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .vote_on_status_update_and_watch(&signer, status_update_id, approve)
                .await
        })
        .await?;
        Ok(())
    }

    /// Fetch an ongoing proposal by ID.
    ///
    /// # Arguments
    /// * `status_update_id` - ID of the status update
    async fn get_status_update(&self, status_update_id: u64) -> Result<PolkaBtcStatusUpdate, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.active_status_updates(status_update_id, head).await?)
    }

    /// Submit extrinsic to report vault theft, consumer should
    /// first check `is_transaction_invalid` to ensure this call
    /// succeeds.
    ///
    /// # Arguments
    /// * `vault_id` - account id for the malicious vault
    /// * `tx_id` - transaction id
    /// * `tx_block_height` - block height to check inclusion
    /// * `merkle_proof` - merkle proof to verify inclusion
    /// * `raw_tx` - raw transaction
    async fn report_vault_theft(
        &self,
        vault_id: AccountId,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .report_vault_theft_and_watch(&signer, vault_id, tx_id, merkle_proof, raw_tx)
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
    async fn is_transaction_invalid(&self, vault_id: AccountId, raw_tx: Vec<u8>) -> Result<bool, Error> {
        Ok(matches!(
            self.rpc_client
                .request(
                    "stakedRelayers_isTransactionInvalid",
                    Params::Array(vec![to_json_value(vault_id)?, to_json_value(raw_tx)?]),
                )
                .await,
            Ok(()),
        ))
    }

    /// Sets the maturity period.
    ///
    /// # Arguments
    ///
    /// * `period` - the number of blocks to wait before a relayer is considered active.
    async fn set_maturity_period(&self, period: u32) -> Result<(), Error> {
        Ok(self.sudo(SetMaturityPeriodCall { period }).await?)
    }

    /// Finalize all active votes; used for testing
    async fn evaluate_status_update(&self, status_update_id: u64) -> Result<(), Error> {
        Ok(self
            .sudo(EvaluateStatusUpdateCall {
                status_update_id,
                _runtime: PhantomData {},
            })
            .await?)
    }

    /// Initializes the relay with the provided block header and height,
    /// should be called automatically by relayer subject to the
    /// result of `is_initialized`.
    ///
    /// # Arguments
    /// * `header` - raw block header
    /// * `height` - starting height
    async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), Error> {
        // TODO: can we initialize the relay through the chain-spec?
        // we would also need to consider re-initialization per governance
        self.with_unique_signer(
            |signer| async move { self.ext_client.initialize_and_watch(&signer, header, height).await },
        )
        .await?;
        Ok(())
    }

    /// Stores a block header in the BTC-Relay.
    ///
    /// # Arguments
    /// * `header` - raw block header
    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        self.with_unique_signer(
            |signer| async move { self.ext_client.store_block_header_and_watch(&signer, header).await },
        )
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
                .map(|header| StoreBlockHeaderCall {
                    _runtime: PhantomData {},
                    raw_block_header: header,
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
}

#[async_trait]
impl SecurityPallet for PolkaBtcProvider {
    /// Get the current security status of the parachain.
    /// Should be one of; `Running`, `Error` or `Shutdown`.
    async fn get_parachain_status(&self) -> Result<StatusCode, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.parachain_status(head).await?)
    }
    /// Return any `ErrorCode`s set in the security module.
    async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.errors(head).await?)
    }
}

#[async_trait]
pub trait IssuePallet {
    /// Request a new issue
    async fn request_issue(
        &self,
        amount: u128,
        vault_id: AccountId,
        griefing_collateral: u128,
    ) -> Result<PolkaBtcRequestIssueEvent, Error>;

    /// Execute a issue request by providing a Bitcoin transaction inclusion proof
    async fn execute_issue(
        &self,
        issue_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    /// Cancel an ongoing issue request
    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error>;

    async fn get_issue_request(&self, issue_id: H256) -> Result<PolkaBtcIssueRequest, Error>;

    async fn get_vault_issue_requests(&self, account_id: AccountId)
        -> Result<Vec<(H256, PolkaBtcIssueRequest)>, Error>;

    async fn get_issue_period(&self) -> Result<u32, Error>;

    async fn set_issue_period(&self, period: u32) -> Result<(), Error>;

    async fn get_all_active_issues(&self) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, Error>;
}

#[async_trait]
impl IssuePallet for PolkaBtcProvider {
    async fn request_issue(
        &self,
        amount: u128,
        vault_id: AccountId,
        griefing_collateral: u128,
    ) -> Result<PolkaBtcRequestIssueEvent, Error> {
        let result = self
            .with_unique_signer(|signer| async move {
                self.ext_client
                    .request_issue_and_watch(&signer, amount, vault_id, griefing_collateral)
                    .await
            })
            .await?;
        result.request_issue()?.ok_or(Error::RequestIssueIDNotFound)
    }

    async fn execute_issue(
        &self,
        issue_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .execute_issue_and_watch(&signer, issue_id, tx_id, merkle_proof, raw_tx)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error> {
        self.with_unique_signer(
            |signer| async move { self.ext_client.cancel_issue_and_watch(&signer, issue_id).await },
        )
        .await?;
        Ok(())
    }

    async fn get_issue_request(&self, issue_id: H256) -> Result<PolkaBtcIssueRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.issue_requests(issue_id, head).await?)
    }

    async fn get_vault_issue_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, Error> {
        let result: Vec<(H256, PolkaBtcIssueRequest)> = self
            .rpc_client
            .request(
                "issue_getVaultIssueRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(result)
    }

    async fn get_issue_period(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.issue_period(head).await?)
    }

    async fn set_issue_period(&self, period: u32) -> Result<(), Error> {
        Ok(self
            .sudo(SetIssuePeriodCall {
                period,
                _runtime: PhantomData {},
            })
            .await?)
    }

    async fn get_all_active_issues(&self) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, Error> {
        let current_height = self.get_current_chain_height().await?;
        let issue_period = self.get_issue_period().await?;

        let mut issue_requests = Vec::new();
        let head = self.get_latest_block_hash().await?;
        let mut iter = self.ext_client.issue_requests_iter(head).await?;
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
    async fn request_redeem(
        &self,
        amount_polka_btc: u128,
        btc_address: BtcAddress,
        vault_id: AccountId,
    ) -> Result<H256, Error>;

    /// Execute a redeem request by providing a Bitcoin transaction inclusion proof
    async fn execute_redeem(
        &self,
        redeem_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    /// Cancel an ongoing redeem request
    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error>;

    async fn get_redeem_request(&self, redeem_id: H256) -> Result<PolkaBtcRedeemRequest, Error>;

    /// Get all open redeem requests requested of the given vault
    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcRedeemRequest)>, Error>;

    async fn get_redeem_period(&self) -> Result<BlockNumber, Error>;

    async fn set_redeem_period(&self, period: u32) -> Result<(), Error>;
}

#[async_trait]
impl RedeemPallet for PolkaBtcProvider {
    async fn request_redeem(
        &self,
        amount_polka_btc: u128,
        btc_address: BtcAddress,
        vault_id: AccountId,
    ) -> Result<H256, Error> {
        let result = self
            .with_unique_signer(|signer| async move {
                self.ext_client
                    .request_redeem_and_watch(&signer, amount_polka_btc, btc_address, vault_id)
                    .await
            })
            .await?;
        if let Some(event) = result.request_redeem()? {
            Ok(event.redeem_id)
        } else {
            Err(Error::RequestRedeemIDNotFound)
        }
    }

    async fn execute_redeem(
        &self,
        redeem_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .execute_redeem_and_watch(&signer, redeem_id, tx_id, merkle_proof, raw_tx)
                .await
        })
        .await?;
        Ok(())
    }

    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .cancel_redeem_and_watch(&signer, redeem_id, reimburse)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_redeem_request(&self, redeem_id: H256) -> Result<PolkaBtcRedeemRequest, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.redeem_requests(redeem_id, head).await?)
    }

    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcRedeemRequest)>, Error> {
        let requests: Vec<(H256, PolkaBtcRedeemRequest)> = self
            .rpc_client
            .request(
                "redeem_getVaultRedeemRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(requests)
    }

    async fn get_redeem_period(&self) -> Result<BlockNumber, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.redeem_period(head).await?)
    }

    async fn set_redeem_period(&self, period: BlockNumber) -> Result<(), Error> {
        Ok(self
            .sudo(SetRedeemPeriodCall {
                period,
                _runtime: PhantomData {},
            })
            .await?)
    }
}

#[async_trait]
pub trait RefundPallet {
    /// Execute a refund request by providing a Bitcoin transaction inclusion proof
    async fn execute_refund(
        &self,
        refund_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    /// Get all open refund requests requested of the given vault
    async fn get_vault_refund_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcRefundRequest)>, Error>;
}

#[async_trait]
impl RefundPallet for PolkaBtcProvider {
    async fn execute_refund(
        &self,
        refund_id: H256,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .execute_refund_and_watch(&signer, refund_id, tx_id, merkle_proof, raw_tx)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_vault_refund_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcRefundRequest)>, Error> {
        let result: Vec<(H256, PolkaBtcRefundRequest)> = self
            .rpc_client
            .request(
                "refund_getVaultRefundRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(result)
    }
}

const BLOCK_WAIT_TIMEOUT: u64 = 6;

#[async_trait]
pub trait BtcRelayPallet {
    async fn get_best_block(&self) -> Result<H256Le, Error>;

    async fn get_best_block_height(&self) -> Result<u32, Error>;

    async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error>;

    async fn get_block_header(&self, hash: H256Le) -> Result<PolkaBtcRichBlockHeader, Error>;

    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error>;

    async fn get_parachain_confirmations(&self) -> Result<BlockNumber, Error>;

    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        btc_confirmations: Option<BlockNumber>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl BtcRelayPallet for PolkaBtcProvider {
    /// Get the hash of the current best tip.
    async fn get_best_block(&self) -> Result<H256Le, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.best_block(head).await?)
    }

    /// Get the current best known height.
    async fn get_best_block_height(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.best_block_height(head).await?)
    }

    /// Get the block hash for the main chain at the specified height.
    ///
    /// # Arguments
    /// * `height` - chain height
    async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.chains_hashes(0, height, head).await?)
    }

    /// Get the corresponding block header for the given hash.
    ///
    /// # Arguments
    /// * `hash` - little endian block hash
    async fn get_block_header(&self, hash: H256Le) -> Result<PolkaBtcRichBlockHeader, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.block_headers(hash, head).await?)
    }

    /// Get the global security parameter k for stable Bitcoin transactions
    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.stable_bitcoin_confirmations(head).await?)
    }

    /// Get the global security parameter for stable parachain confirmations
    async fn get_parachain_confirmations(&self) -> Result<BlockNumber, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.stable_parachain_confirmations(head).await?)
    }

    /// Wait until Bitcoin block is submitted to the relay
    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        btc_confirmations: Option<BlockNumber>,
    ) -> Result<(), Error> {
        let get_bitcoin_confirmations = async {
            if let Some(btc_confirmations) = btc_confirmations {
                Ok(btc_confirmations)
            } else {
                self.get_bitcoin_confirmations().await
            }
        };

        let (bitcoin_confirmations, parachain_confirmations) =
            futures::future::try_join(get_bitcoin_confirmations, self.get_parachain_confirmations()).await?;

        async fn has_sufficient_confirmations(
            btc_parachain: &PolkaBtcProvider,
            rich_block_header: &PolkaBtcRichBlockHeader,
            bitcoin_confirmations: u32,
            parachain_confirmations: BlockNumber,
        ) -> Result<bool, Error> {
            let (bitcoin_height, parachain_height) = futures::future::try_join(
                async { btc_parachain.get_best_block_height().await.map_err(Error::from) },
                async {
                    Ok(btc_parachain
                        .get_latest_block()
                        .await?
                        .ok_or(Error::BlockNotFound)?
                        .block
                        .header
                        .number)
                },
            )
            .await?;

            let is_confirmed_bitcoin = rich_block_header.block_height + bitcoin_confirmations <= bitcoin_height;
            let is_confirmed_parachain = rich_block_header.para_height + parachain_confirmations <= parachain_height;
            Ok(is_confirmed_bitcoin && is_confirmed_parachain)
        }

        loop {
            match self.get_block_header(block_hash).await {
                // rpc returns zero-initialized storage items if not set, therefore
                // a block header only exists if the height is non-zero
                Ok(block_header)
                    if block_header.block_height > 0
                        && has_sufficient_confirmations(
                            &self,
                            &block_header,
                            bitcoin_confirmations,
                            parachain_confirmations,
                        )
                        .await? =>
                {
                    return Ok(());
                }
                _ => {
                    log::trace!(
                        "block {} not found or confirmed, waiting for {} seconds",
                        block_hash,
                        BLOCK_WAIT_TIMEOUT
                    );
                    delay_for(Duration::from_secs(BLOCK_WAIT_TIMEOUT)).await;
                    continue;
                }
            };
        }
    }
}

#[async_trait]
pub trait VaultRegistryPallet {
    async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, Error>;

    async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, Error>;

    async fn register_vault(&self, collateral: u128, public_key: BtcPublicKey) -> Result<(), Error>;

    async fn lock_additional_collateral(&self, amount: u128) -> Result<(), Error>;

    async fn withdraw_collateral(&self, amount: u128) -> Result<(), Error>;

    async fn update_public_key(&self, public_key: BtcPublicKey) -> Result<(), Error>;

    async fn register_address(&self, btc_address: BtcAddress) -> Result<(), Error>;

    async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, Error>;

    async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, Error>;

    async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, Error>;
}

#[async_trait]
impl VaultRegistryPallet for PolkaBtcProvider {
    /// Fetch a specific vault by ID.
    ///
    /// # Arguments
    /// * `vault_id` - account ID of the vault
    ///
    /// # Errors
    /// * `VaultNotFound` - if the rpc returned a default value rather than the vault we want
    /// * `VaultLiquidated` - if the vault is liquidated
    /// * `VaultCommittedTheft` - if the vault is stole BTC
    async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, Error> {
        let head = self.get_latest_block_hash().await?;
        match self.ext_client.vaults(vault_id.clone(), head).await {
            Ok(PolkaBtcVault {
                status: VaultStatus::Liquidated,
                ..
            }) => Err(Error::VaultLiquidated),
            Ok(PolkaBtcVault {
                status: VaultStatus::CommittedTheft,
                ..
            }) => Err(Error::VaultCommittedTheft),
            Ok(vault) if vault.id == vault_id => Ok(vault),
            Ok(_) => Err(Error::VaultNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Fetch all active vaults.
    async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, Error> {
        let mut vaults = Vec::new();
        let head = self.get_latest_block_hash().await?;
        let mut iter = self.ext_client.vaults_iter(head).await?;
        while let Some((_, account)) = iter.next().await? {
            if let VaultStatus::Active = account.status {
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
    async fn register_vault(&self, collateral: u128, public_key: BtcPublicKey) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .register_vault_and_watch(&signer, collateral, public_key)
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
    async fn lock_additional_collateral(&self, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client
                .lock_additional_collateral_and_watch(&signer, amount)
                .await
        })
        .await?;
        Ok(())
    }

    /// Withdraws `amount` of the collateral from the amount locked by
    /// the vault corresponding to the origin account
    /// The collateral left after withdrawal must be more
    /// (free or used in backing issued PolkaBTC) than MinimumCollateralVault
    /// and above the SecureCollateralThreshold. Collateral that is currently
    /// being used to back issued PolkaBTC remains locked until the Vault
    /// is used for a redeem request (full release can take multiple redeem requests).
    ///
    /// # Arguments
    /// * `amount` - the amount of collateral to withdraw
    async fn withdraw_collateral(&self, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.withdraw_collateral_and_watch(&signer, amount).await
        })
        .await?;
        Ok(())
    }

    /// Update the default BTC public key for the vault corresponding to the signer.
    ///
    /// # Arguments
    /// * `public_key` - the new public key of the vault
    async fn update_public_key(&self, public_key: BtcPublicKey) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.update_public_key_and_watch(&signer, public_key).await
        })
        .await?;
        Ok(())
    }

    /// Register a new BTC address, useful for change addresses.
    ///
    /// # Arguments
    /// * `btc_address` - the new btc address of the vault
    async fn register_address(&self, btc_address: BtcAddress) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.ext_client.register_address_and_watch(&signer, btc_address).await
        })
        .await?;
        Ok(())
    }

    /// Custom RPC that calculates the exact collateral required to cover the BTC amount.
    ///
    /// # Arguments
    /// * `amount_btc` - amount of btc to cover
    async fn get_required_collateral_for_polkabtc(&self, amount_btc: u128) -> Result<u128, Error> {
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "vaultRegistry_getRequiredCollateralForPolkabtc",
                Params::Array(vec![to_json_value(BalanceWrapper { amount: amount_btc })?]),
            )
            .await?;

        Ok(result.amount)
    }

    /// Get the amount of collateral required for the given vault to be at the
    /// current SecureCollateralThreshold with the current exchange rate
    async fn get_required_collateral_for_vault(&self, vault_id: AccountId) -> Result<u128, Error> {
        let result: BalanceWrapper<_> = self
            .rpc_client
            .request(
                "vaultRegistry_getRequiredCollateralForVault",
                Params::Array(vec![to_json_value(vault_id)?]),
            )
            .await?;

        Ok(result.amount)
    }

    /// Custom RPC that tests whether a vault is below the auction threshold.
    ///
    /// # Arguments
    /// * `vault_id` - vault account to check
    async fn is_vault_below_auction_threshold(&self, vault_id: AccountId) -> Result<bool, Error> {
        Ok(self
            .rpc_client
            .request(
                "vaultRegistry_isVaultBelowAuctionThreshold",
                Params::Array(vec![to_json_value(vault_id)?]),
            )
            .await?)
    }
}

#[async_trait]
pub trait FeePallet {
    async fn get_issue_griefing_collateral(&self) -> Result<FixedU128, Error>;
    async fn get_issue_fee(&self) -> Result<FixedU128, Error>;
    async fn get_replace_griefing_collateral(&self) -> Result<FixedU128, Error>;
}

#[async_trait]
impl FeePallet for PolkaBtcProvider {
    async fn get_issue_griefing_collateral(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.issue_griefing_collateral(head).await?)
    }

    async fn get_issue_fee(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.issue_fee(head).await?)
    }

    async fn get_replace_griefing_collateral(&self) -> Result<FixedU128, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.ext_client.replace_griefing_collateral(head).await?)
    }
}
