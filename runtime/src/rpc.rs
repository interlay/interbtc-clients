pub use module_exchange_rate_oracle::BtcTxFeesPerByte;

use async_trait::async_trait;
use core::marker::PhantomData;
use futures::{stream::StreamExt, SinkExt};
use jsonrpsee::{
    common::{to_value as to_json_value, Params},
    Client as RpcClient,
};
use log::{info, trace};
use module_exchange_rate_oracle_rpc_runtime_api::BalanceWrapper;
use sp_arithmetic::FixedU128;
use sp_core::sr25519::Pair as KeyPair;
use sp_core::H256;
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use substrate_subxt::Error as XtError;
use substrate_subxt::EventTypeRegistry;
use substrate_subxt::{
    sudo::*, Call, Client, ClientBuilder, Event, EventSubscription, EventsDecoder, PairSigner,
    Signer,
};
use tokio::sync::RwLock;
use tokio::time::{delay_for, timeout};

use crate::btc_relay::*;
use crate::exchange_rate_oracle::*;
use crate::fee::*;
use crate::issue::*;
use crate::pallets::Core;
use crate::redeem::*;
use crate::refund::*;
use crate::replace::*;
use crate::security::*;
use crate::staked_relayers::*;
use crate::timestamp::*;
use crate::types::*;
use crate::vault_registry::*;
use crate::Error;
use crate::PolkaBtcRuntime;
use crate::{balances_dot::*, BlockNumber};

use crate::error::{IoErrorKind, WsNewDnsError, WsNewError};

const RETRY_DURATION: Duration = Duration::from_millis(1000);

#[derive(Clone)]
pub struct PolkaBtcProvider {
    rpc_client: RpcClient,
    ext_client: Client<PolkaBtcRuntime>,
    signer: Arc<RwLock<PairSigner<PolkaBtcRuntime, KeyPair>>>,
    account_id: AccountId,
}

impl PolkaBtcProvider {
    pub async fn new<P: Into<jsonrpsee::Client>>(
        rpc_client: P,
        mut signer: PairSigner<PolkaBtcRuntime, KeyPair>,
    ) -> Result<Self, Error> {
        let account_id = signer.account_id().clone();
        let rpc_client = rpc_client.into();
        let ext_client = ClientBuilder::<PolkaBtcRuntime>::new()
            .set_client(rpc_client.clone())
            .build()
            .await?;

        // query account info in order to get the nonce value used for communication
        let account_info = crate::frame_system::AccountStoreExt::account(
            &ext_client,
            account_id.clone(),
            Option::<H256>::None,
        )
        .await?;
        signer.set_nonce(account_info.nonce);

        Ok(Self {
            rpc_client,
            ext_client,
            signer: Arc::new(RwLock::new(signer)),
            account_id,
        })
    }

    pub async fn from_url(
        url: &String,
        signer: PairSigner<PolkaBtcRuntime, KeyPair>,
    ) -> Result<Self, Error> {
        let rpc_client = if url.starts_with("ws://") || url.starts_with("wss://") {
            jsonrpsee::ws_client(url).await?
        } else {
            jsonrpsee::http_client(url)
        };

        Self::new(rpc_client, signer).await
    }

    pub async fn from_url_with_retry(
        url: String,
        signer: PairSigner<PolkaBtcRuntime, KeyPair>,
        timeout_duration: Duration,
    ) -> Result<Self, Error> {
        info!("Connecting to the btc-parachain...");
        timeout(timeout_duration, async move {
            loop {
                match Self::from_url(&url, signer.clone()).await {
                    Err(Error::WsHandshake(WsNewDnsError::Connect(WsNewError::Io(err))))
                        if err.kind() == IoErrorKind::ConnectionRefused =>
                    {
                        trace!("could not connect to parachain");
                        delay_for(RETRY_DURATION).await;
                        continue;
                    }
                    Ok(rpc) => {
                        info!("Connected!");
                        return Ok(rpc);
                    }
                    Err(err) => return Err(err),
                }
            }
        })
        .await?
    }

    /// Gets a copy of the signer with a unique nonce
    async fn get_unique_signer(&self) -> PairSigner<PolkaBtcRuntime, KeyPair> {
        // TODO: refresh from account store
        let mut signer = self.signer.write().await;
        // return the current value, increment afterwards
        let ret = signer.clone();
        signer.increment_nonce();
        ret
    }

    pub async fn get_latest_block_hash(&self) -> Result<Option<H256>, Error> {
        Ok(self.ext_client.block_hash(None).await?)
    }

    pub async fn get_latest_block(&self) -> Result<Option<PolkaBtcBlock>, Error> {
        Ok(self.ext_client.block::<H256>(None).await?)
    }

    /// Fetch all active vaults.
    pub async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, Error> {
        let mut vaults = Vec::new();
        let mut iter = self.ext_client.vaults_iter(None).await?;
        while let Some((_, account)) = iter.next().await? {
            vaults.push(account);
        }
        Ok(vaults)
    }

    /// Subscribe to new parachain blocks.
    pub async fn on_block<F, R>(&self, on_block: F) -> Result<(), Error>
    where
        F: Fn(PolkaBtcHeader) -> R,
        R: Future<Output = Result<(), Error>>,
    {
        let mut sub = self.ext_client.subscribe_finalized_blocks().await?;
        loop {
            on_block(sub.next().await).await?;
        }
    }

    /// Subscription service that should listen forever, only returns if the initial subscription
    /// cannot be established. Calls `on_error` when an error event has been received, or when an
    /// event has been received that failed to be decoded into a raw event.
    ///
    /// # Arguments
    /// * `on_error` - callback for decoding errors, is not allowed to take too long
    pub async fn on_event_error<E: Fn(XtError)>(&self, on_error: E) -> Result<(), Error> {
        let sub = self.ext_client.subscribe_events().await?;
        let decoder = EventsDecoder::<PolkaBtcRuntime>::new(
            self.ext_client.metadata().clone(),
            EventTypeRegistry::new(),
        );

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
        E: Fn(XtError),
    {
        let sub = self.ext_client.subscribe_events().await?;
        let decoder = EventsDecoder::<PolkaBtcRuntime>::new(
            self.ext_client.metadata().clone(),
            EventTypeRegistry::new(),
        );

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, &decoder);
        sub.filter_event::<T>();

        let (tx, mut rx) = futures::channel::mpsc::channel::<T>(32);

        // two tasks: one for event listening and one for callback calling
        futures::future::try_join(
            async move {
                let tx = &tx;
                while let Some(result) = sub.next().await {
                    if let Ok(raw_event) = result {
                        trace!("raw event: {:?}", raw_event);
                        let decoded = T::decode(&mut &raw_event.data[..]);
                        match decoded {
                            Ok(event) => {
                                trace!("decoded event: {:?}", event);
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
                    match rx.next().await {
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
        let encoded = self.ext_client.encode(call)?;
        self.ext_client
            .sudo_and_watch(&self.get_unique_signer().await, &encoded)
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
        let query_result = self.ext_client.block(Option::<H256>::None).await?;
        match query_result {
            Some(x) => Ok(x.block.header.number),
            None => Err(Error::BlockNotFound),
        }
    }

    async fn get_blockchain_height_at(&self, parachain_height: u32) -> Result<u32, Error> {
        let hash = self
            .ext_client
            .block_hash(Some(parachain_height.into()))
            .await?;
        Ok(self.ext_client.best_block_height(hash).await?)
    }

    fn get_account_id(&self) -> &AccountId {
        &self.account_id
    }
}

#[async_trait]
pub trait DotBalancesPallet {
    async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn get_free_dot_balance_for_id(
        &self,
        id: AccountId,
    ) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error>;

    async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), Error>;
}

#[async_trait]
impl DotBalancesPallet for PolkaBtcProvider {
    async fn get_free_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        Ok(Self::get_free_dot_balance_for_id(&self, self.account_id.clone()).await?)
    }

    async fn get_free_dot_balance_for_id(
        &self,
        id: AccountId,
    ) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        Ok(self.ext_client.account(id.clone(), None).await?.free)
    }

    async fn get_reserved_dot_balance(&self) -> Result<<PolkaBtcRuntime as Core>::Balance, Error> {
        Ok(self
            .ext_client
            .account(self.account_id.clone(), None)
            .await?
            .reserved)
    }

    async fn transfer_to(&self, destination: AccountId, amount: u128) -> Result<(), Error> {
        self.ext_client
            .transfer_and_watch(&self.get_unique_signer().await, &destination, amount)
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
    async fn request_replace(&self, amount: u128, griefing_collateral: u128)
        -> Result<H256, Error>;

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
    async fn accept_replace(
        &self,
        replace_id: H256,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error>;

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
}

#[async_trait]
impl ReplacePallet for PolkaBtcProvider {
    async fn request_replace(
        &self,
        amount: u128,
        griefing_collateral: u128,
    ) -> Result<H256, Error> {
        let result = self
            .ext_client
            .request_replace_and_watch(&self.get_unique_signer().await, amount, griefing_collateral)
            .await?;

        if let Some(event) = result.request_replace()? {
            Ok(event.replace_id)
        } else {
            Err(Error::RequestReplaceIDNotFound)
        }
    }

    async fn withdraw_replace(&self, replace_id: H256) -> Result<(), Error> {
        self.ext_client
            .withdraw_replace_and_watch(&self.get_unique_signer().await, replace_id)
            .await?;
        Ok(())
    }

    async fn accept_replace(
        &self,
        replace_id: H256,
        collateral: u128,
        btc_address: BtcAddress,
    ) -> Result<(), Error> {
        self.ext_client
            .accept_replace_and_watch(
                &self.get_unique_signer().await,
                replace_id,
                collateral,
                btc_address,
            )
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
        self.ext_client
            .auction_replace_and_watch(
                &self.get_unique_signer().await,
                old_vault,
                btc_amount,
                collateral,
                btc_address,
            )
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
        self.ext_client
            .execute_replace_and_watch(
                &self.get_unique_signer().await,
                replace_id,
                tx_id,
                merkle_proof,
                raw_tx,
            )
            .await?;
        Ok(())
    }

    async fn cancel_replace(&self, replace_id: H256) -> Result<(), Error> {
        self.ext_client
            .cancel_replace_and_watch(&self.get_unique_signer().await, replace_id)
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
        Ok(self.ext_client.replace_period(None).await?)
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
        Ok(self.ext_client.replace_requests(replace_id, None).await?)
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
        Ok(self.ext_client.now(None).await?)
    }
}

#[async_trait]
pub trait ExchangeRateOraclePallet {
    async fn get_exchange_rate_info(&self) -> Result<(FixedU128, u64, u64), Error>;

    async fn set_exchange_rate_info(&self, dot_per_btc: FixedU128) -> Result<(), Error>;

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
        let get_rate = self.ext_client.exchange_rate(None);
        let get_time = self.ext_client.last_exchange_rate_time(None);
        let get_delay = self.ext_client.max_delay(None);

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
        self.ext_client
            .set_exchange_rate_and_watch(&self.get_unique_signer().await, dot_per_btc)
            .await?;
        Ok(())
    }

    /// Sets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next x blocks
    ///
    /// # Arguments
    /// * `fast` - The estimated Satoshis per bytes to get included in the next block (~10 min)
    /// * `half` - The estimated Satoshis per bytes to get included in the next 3 blocks (~half hour)
    /// * `hour` - The estimated Satoshis per bytes to get included in the next 6 blocks (~hour)
    async fn set_btc_tx_fees_per_byte(&self, fast: u32, half: u32, hour: u32) -> Result<(), Error> {
        self.ext_client
            .set_btc_tx_fees_per_byte_and_watch(&self.get_unique_signer().await, fast, half, hour)
            .await?;
        Ok(())
    }

    /// Gets the estimated Satoshis per bytes required to get a Bitcoin transaction included in
    /// in the next x blocks
    async fn get_btc_tx_fees_per_byte(&self) -> Result<BtcTxFeesPerByte, Error> {
        Ok(self.ext_client.satoshi_per_bytes(None).await?)
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

    async fn vote_on_status_update(
        &self,
        status_update_id: u64,
        approve: bool,
    ) -> Result<(), Error>;

    async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, Error>;

    async fn report_oracle_offline(&self) -> Result<(), Error>;

    async fn report_vault_theft(
        &self,
        vault_id: AccountId,
        tx_id: H256Le,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    async fn is_transaction_invalid(
        &self,
        vault_id: AccountId,
        raw_tx: Vec<u8>,
    ) -> Result<bool, Error>;

    async fn set_maturity_period(&self, period: u32) -> Result<(), Error>;

    async fn evaluate_status_update(&self, status_update_id: u64) -> Result<(), Error>;
}

#[async_trait]
impl StakedRelayerPallet for PolkaBtcProvider {
    /// Get the stake registered for this staked relayer.
    async fn get_active_stake(&self) -> Result<u128, Error> {
        Ok(self.get_active_stake_by_id(self.account_id.clone()).await?)
    }

    /// Get the stake registered for this staked relayer.
    async fn get_active_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error> {
        Ok(self
            .ext_client
            .active_staked_relayers(&account_id, None)
            .await?
            .stake)
    }

    /// Get the stake registered for this inactive staked relayer.
    async fn get_inactive_stake_by_id(&self, account_id: AccountId) -> Result<u128, Error> {
        Ok(self
            .ext_client
            .inactive_staked_relayers(&account_id, None)
            .await?
            .stake)
    }

    /// Submit extrinsic to register the staked relayer.
    ///
    /// # Arguments
    /// * `stake` - deposit
    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error> {
        self.ext_client
            .register_staked_relayer_and_watch(&self.get_unique_signer().await, stake)
            .await?;
        Ok(())
    }

    /// Submit extrinsic to deregister the staked relayer.
    async fn deregister_staked_relayer(&self) -> Result<(), Error> {
        self.ext_client
            .deregister_staked_relayer_and_watch(&self.get_unique_signer().await)
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
        self.ext_client
            .suggest_status_update_and_watch(
                &self.get_unique_signer().await,
                deposit,
                status_code,
                add_error,
                remove_error,
                block_hash,
                message.into_bytes(),
            )
            .await?;
        Ok(())
    }

    /// Vote on an ongoing proposal by ID.
    ///
    /// # Arguments
    /// * `status_update_id` - ID of the status update
    /// * `approve` - whether to approve or reject the proposal
    async fn vote_on_status_update(
        &self,
        status_update_id: u64,
        approve: bool,
    ) -> Result<(), Error> {
        self.ext_client
            .vote_on_status_update_and_watch(
                &self.get_unique_signer().await,
                status_update_id,
                approve,
            )
            .await?;
        Ok(())
    }

    /// Fetch an ongoing proposal by ID.
    ///
    /// # Arguments
    /// * `status_update_id` - ID of the status update
    async fn get_status_update(
        &self,
        status_update_id: u64,
    ) -> Result<PolkaBtcStatusUpdate, Error> {
        Ok(self
            .ext_client
            .active_status_updates(status_update_id, None)
            .await?)
    }

    /// Submit extrinsic to report that the oracle is offline.
    async fn report_oracle_offline(&self) -> Result<(), Error> {
        self.ext_client
            .report_oracle_offline_and_watch(&self.get_unique_signer().await)
            .await?;
        Ok(())
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
        self.ext_client
            .report_vault_theft_and_watch(
                &self.get_unique_signer().await,
                vault_id,
                tx_id,
                merkle_proof,
                raw_tx,
            )
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
    async fn is_transaction_invalid(
        &self,
        vault_id: AccountId,
        raw_tx: Vec<u8>,
    ) -> Result<bool, Error> {
        Ok(
            match self
                .rpc_client
                .request(
                    "stakedRelayers_isTransactionInvalid",
                    Params::Array(vec![to_json_value(vault_id)?, to_json_value(raw_tx)?]),
                )
                .await
            {
                Ok(()) => true,
                _ => false,
            },
        )
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
        Ok(self.ext_client.parachain_status(None).await?)
    }
    /// Return any `ErrorCode`s set in the security module.
    async fn get_error_codes(&self) -> Result<BTreeSet<ErrorCode>, Error> {
        Ok(self.ext_client.errors(None).await?)
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

    async fn get_vault_issue_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcIssueRequest)>, Error>;

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
            .ext_client
            .request_issue_and_watch(
                &self.get_unique_signer().await,
                amount,
                vault_id,
                griefing_collateral,
            )
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
        self.ext_client
            .execute_issue_and_watch(
                &self.get_unique_signer().await,
                issue_id,
                tx_id,
                merkle_proof,
                raw_tx,
            )
            .await?;
        Ok(())
    }

    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error> {
        self.ext_client
            .cancel_issue_and_watch(&self.get_unique_signer().await, issue_id)
            .await?;
        Ok(())
    }

    async fn get_issue_request(&self, issue_id: H256) -> Result<PolkaBtcIssueRequest, Error> {
        Ok(self.ext_client.issue_requests(issue_id, None).await?)
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
        Ok(self.ext_client.issue_period(None).await?)
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
        let mut iter = self.ext_client.issue_requests_iter(None).await?;
        while let Some((issue_id, request)) = iter.next().await? {
            if !request.completed
                && !request.cancelled
                && request.opentime + issue_period > current_height
            {
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
            .ext_client
            .request_redeem_and_watch(
                &self.get_unique_signer().await,
                amount_polka_btc,
                btc_address,
                vault_id,
            )
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
        self.ext_client
            .execute_redeem_and_watch(
                &self.get_unique_signer().await,
                redeem_id,
                tx_id,
                merkle_proof,
                raw_tx,
            )
            .await?;
        Ok(())
    }

    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error> {
        self.ext_client
            .cancel_redeem_and_watch(&self.get_unique_signer().await, redeem_id, reimburse)
            .await?;
        Ok(())
    }

    async fn get_redeem_request(&self, redeem_id: H256) -> Result<PolkaBtcRedeemRequest, Error> {
        Ok(self.ext_client.redeem_requests(redeem_id, None).await?)
    }

    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, PolkaBtcRedeemRequest)>, Error> {
        let result: Vec<(H256, PolkaBtcRedeemRequest)> = self
            .rpc_client
            .request(
                "redeem_getVaultRedeemRequests",
                Params::Array(vec![to_json_value(account_id)?]),
            )
            .await?;

        Ok(result)
    }

    async fn get_redeem_period(&self) -> Result<BlockNumber, Error> {
        Ok(self.ext_client.redeem_period(None).await?)
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
        self.ext_client
            .execute_refund_and_watch(
                &self.get_unique_signer().await,
                refund_id,
                tx_id,
                merkle_proof,
                raw_tx,
            )
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

    async fn initialize_btc_relay(
        &self,
        header: RawBlockHeader,
        height: BitcoinBlockHeight,
    ) -> Result<(), Error>;

    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error>;

    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error>;

    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error>;

    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        num_confirmations: u32,
    ) -> Result<(), Error>;
}

#[async_trait]
impl BtcRelayPallet for PolkaBtcProvider {
    /// Get the hash of the current best tip.
    async fn get_best_block(&self) -> Result<H256Le, Error> {
        Ok(self.ext_client.best_block(None).await?)
    }

    /// Get the current best known height.
    async fn get_best_block_height(&self) -> Result<u32, Error> {
        Ok(self.ext_client.best_block_height(None).await?)
    }

    /// Get the block hash for the main chain at the specified height.
    ///
    /// # Arguments
    /// * `height` - chain height
    async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error> {
        Ok(self.ext_client.chains_hashes(0, height, None).await?)
    }

    /// Get the corresponding block header for the given hash.
    ///
    /// # Arguments
    /// * `hash` - little endian block hash
    async fn get_block_header(&self, hash: H256Le) -> Result<PolkaBtcRichBlockHeader, Error> {
        Ok(self.ext_client.block_headers(hash, None).await?)
    }

    /// Initializes the relay with the provided block header and height,
    /// should be called automatically by `relayer_core` subject to the
    /// result of `is_initialized`.
    ///
    /// # Arguments
    /// * `header` - raw block header
    /// * `height` - starting height
    async fn initialize_btc_relay(
        &self,
        header: RawBlockHeader,
        height: BitcoinBlockHeight,
    ) -> Result<(), Error> {
        // TODO: can we initialize the relay through the chain-spec?
        // we would also need to consider re-initialization per governance
        self.ext_client
            .initialize_and_watch(&self.get_unique_signer().await, header, height)
            .await?;
        Ok(())
    }

    /// Stores a block header in the BTC-Relay.
    ///
    /// # Arguments
    /// * `header` - raw block header
    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        self.ext_client
            .store_block_header_and_watch(&self.get_unique_signer().await, header)
            .await?;
        Ok(())
    }

    /// Stores multiple block headers in the BTC-Relay.
    ///
    /// # Arguments
    /// * `headers` - raw block headers
    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error> {
        self.ext_client
            .store_block_headers_and_watch(&self.get_unique_signer().await, headers)
            .await?;
        Ok(())
    }

    /// Get the global security parameter k for stable Bitcoin transactions
    async fn get_bitcoin_confirmations(&self) -> Result<u32, Error> {
        Ok(self.ext_client.stable_bitcoin_confirmations(None).await?)
    }

    /// Wait until Bitcoin block is submitted to the relay
    async fn wait_for_block_in_relay(
        &self,
        block_hash: H256Le,
        num_confirmations: u32,
    ) -> Result<(), Error> {
        loop {
            match self.get_block_header(block_hash).await {
                // rpc returns zero-initialized storage items if not set, therefore
                // a block header only exists if the height is non-zero
                Ok(block_header)
                    if block_header.block_height > 0
                        && block_header.block_height + num_confirmations
                            <= self.get_best_block_height().await? =>
                {
                    return Ok(());
                }
                _ => {
                    trace!(
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

    async fn register_vault(&self, collateral: u128, public_key: BtcPublicKey)
        -> Result<(), Error>;

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
    async fn get_vault(&self, vault_id: AccountId) -> Result<PolkaBtcVault, Error> {
        let vault: PolkaBtcVault = self.ext_client.vaults(vault_id.clone(), None).await?;
        if vault.id == vault_id {
            Ok(vault)
        } else {
            Err(Error::VaultNotFound)
        }
    }

    /// Fetch all active vaults.
    async fn get_all_vaults(&self) -> Result<Vec<PolkaBtcVault>, Error> {
        let mut vaults = Vec::new();
        let mut iter = self.ext_client.vaults_iter(None).await?;
        while let Some((_, account)) = iter.next().await? {
            vaults.push(account);
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
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), Error> {
        self.ext_client
            .register_vault_and_watch(&self.get_unique_signer().await, collateral, public_key)
            .await?;
        Ok(())
    }

    /// Locks additional collateral as a security against stealing the
    /// Bitcoin locked with it.
    ///
    /// # Arguments
    /// * `amount` - the amount of extra collateral to lock
    async fn lock_additional_collateral(&self, amount: u128) -> Result<(), Error> {
        self.ext_client
            .lock_additional_collateral_and_watch(&self.get_unique_signer().await, amount)
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
        self.ext_client
            .withdraw_collateral_and_watch(&self.get_unique_signer().await, amount)
            .await?;
        Ok(())
    }

    /// Update the default BTC public key for the vault corresponding to the signer.
    ///
    /// # Arguments
    /// * `public_key` - the new public key of the vault
    async fn update_public_key(&self, public_key: BtcPublicKey) -> Result<(), Error> {
        self.ext_client
            .update_public_key_and_watch(&self.get_unique_signer().await, public_key)
            .await?;
        Ok(())
    }

    /// Register a new BTC address, useful for change addresses.
    ///
    /// # Arguments
    /// * `btc_address` - the new btc address of the vault
    async fn register_address(&self, btc_address: BtcAddress) -> Result<(), Error> {
        self.ext_client
            .register_address_and_watch(&self.get_unique_signer().await, btc_address)
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
        Ok(self.ext_client.issue_griefing_collateral(None).await?)
    }

    async fn get_issue_fee(&self) -> Result<FixedU128, Error> {
        Ok(self.ext_client.issue_fee(None).await?)
    }

    async fn get_replace_griefing_collateral(&self) -> Result<FixedU128, Error> {
        Ok(self.ext_client.replace_griefing_collateral(None).await?)
    }
}
