use crate::{
    conn::{new_websocket_client, new_websocket_client_with_retry},
    metadata,
    metadata::{DispatchError, Event as InterBtcEvent},
    notify_retry,
    types::*,
    AccountId, AssetRegistry, CurrencyId, Error, InterBtcRuntime, InterBtcSigner, RetryPolicy, RichH256Le, SubxtError,
};
use async_trait::async_trait;
use codec::{Decode, Encode};
use futures::{future::join_all, stream::StreamExt, FutureExt, SinkExt};
use module_oracle_rpc_runtime_api::BalanceWrapper;
use primitives::UnsignedFixedPoint;
use serde_json::Value;
use sp_runtime::FixedPointNumber;
use std::{collections::BTreeSet, future::Future, ops::RangeInclusive, sync::Arc, time::Duration};
use subxt::{
    rpc::{rpc_params, ClientT},
    BasicError, Client as SubxtClient, ClientBuilder as SubxtClientBuilder, Event, PolkadotExtrinsicParams, RpcClient,
    TransactionEvents, TransactionProgress,
};
use tokio::{
    sync::RwLock,
    time::{sleep, timeout},
};

// timeout before retrying parachain calls (5 minutes)
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(300);

// timeout before re-verifying block header inclusion
const BLOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(6);

// sanity check to be sure that testing-utils is not accidentally selected
#[cfg(all(
    any(test, feature = "testing-utils"),
    not(feature = "parachain-metadata-kintsugi-testnet")
))]
compile_error!("Tests are only supported for the kintsugi testnet metadata");

cfg_if::cfg_if! {
    if #[cfg(feature = "parachain-metadata-interlay")] {
        const DEFAULT_SPEC_VERSION: RangeInclusive<u32> = 1018000..=1018000;
        const DEFAULT_SPEC_NAME: &str = "interlay-parachain";
        pub const SS58_PREFIX: u16 = 2032;
    } else if #[cfg(feature = "parachain-metadata-kintsugi")] {
        const DEFAULT_SPEC_VERSION: RangeInclusive<u32> = 1018000..=1018000;
        const DEFAULT_SPEC_NAME: &str = "kintsugi-parachain";
        pub const SS58_PREFIX: u16 = 2092;
    } else if #[cfg(feature = "parachain-metadata-interlay-testnet")] {
        const DEFAULT_SPEC_VERSION: RangeInclusive<u32> = 1018000..=1018000;
        const DEFAULT_SPEC_NAME: &str = "testnet-interlay";
        pub const SS58_PREFIX: u16 = 2032;
    }  else if #[cfg(feature = "parachain-metadata-kintsugi-testnet")] {
        const DEFAULT_SPEC_VERSION: RangeInclusive<u32> = 1018000..=1018000;
        // fun workaround to migrate allowed spec name
        struct ThisOrThat<'a>(&'a str, &'a str);
        impl<'a> PartialEq<String> for ThisOrThat<'a> {
            fn eq(&self, other: &String) -> bool {
                self.0 == other || self.1 == other
            }
        }
        impl<'a> From<ThisOrThat<'a>> for String {
            fn from(tot: ThisOrThat<'a>) -> String {
                tot.1.into()
            }
        }
        const DEFAULT_SPEC_NAME: ThisOrThat = ThisOrThat(
            "testnet-parachain",
            "testnet-kintsugi"
        );
        pub const SS58_PREFIX: u16 = 2092;
    }
}

type RuntimeApi = metadata::RuntimeApi<InterBtcRuntime, PolkadotExtrinsicParams<InterBtcRuntime>>;
pub(crate) type ShutdownSender = tokio::sync::broadcast::Sender<Option<()>>;
pub(crate) type FeeRateUpdateSender = tokio::sync::broadcast::Sender<FixedU128>;
pub type FeeRateUpdateReceiver = tokio::sync::broadcast::Receiver<FixedU128>;

#[derive(Clone)]
pub struct InterBtcParachain {
    ext_client: Arc<SubxtClient<InterBtcRuntime>>,
    signer: Arc<RwLock<InterBtcSigner>>,
    account_id: AccountId,
    api: Arc<RuntimeApi>,
    shutdown_tx: ShutdownSender,
    fee_rate_update_tx: FeeRateUpdateSender,
    pub native_currency_id: CurrencyId,
    pub relay_chain_currency_id: CurrencyId,
    pub wrapped_currency_id: CurrencyId,
}

impl InterBtcParachain {
    pub async fn new<P: Into<RpcClient>>(
        rpc_client: P,
        signer: InterBtcSigner,
        shutdown_tx: ShutdownSender,
    ) -> Result<Self, Error> {
        let account_id = signer.account_id().clone();
        let ext_client = SubxtClientBuilder::new().set_client(rpc_client).build().await?;
        let api: RuntimeApi = ext_client.clone().to_runtime_api();

        let runtime_version = ext_client.rpc().runtime_version(None).await?;
        let spec_name: String = runtime_version
            .other
            .get("specName")
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
            .unwrap_or_default();
        if DEFAULT_SPEC_NAME == spec_name {
            log::info!("spec_name={}", spec_name);
        } else {
            return Err(Error::ParachainMetadataMismatch(DEFAULT_SPEC_NAME.into(), spec_name));
        }

        if DEFAULT_SPEC_VERSION.contains(&runtime_version.spec_version) {
            log::info!("spec_version={}", runtime_version.spec_version);
            log::info!("transaction_version={}", runtime_version.transaction_version);
        } else {
            return Err(Error::InvalidSpecVersion(
                *DEFAULT_SPEC_VERSION.start(),
                *DEFAULT_SPEC_VERSION.end(),
                runtime_version.spec_version,
            ));
        }

        let currency_constants = api.constants().currency();
        let native_currency_id = currency_constants.get_native_currency_id()?;
        let relay_chain_currency_id = currency_constants.get_relay_chain_currency_id()?;
        let wrapped_currency_id = currency_constants.get_wrapped_currency_id()?;

        // low capacity channel since we generally only care about the newest value, so it's ok
        // if we miss an event
        let (fee_rate_update_tx, _) = tokio::sync::broadcast::channel(2);

        let parachain_rpc = Self {
            ext_client: Arc::new(ext_client),
            api: Arc::new(api),
            signer: Arc::new(RwLock::new(signer)),
            account_id,
            shutdown_tx,
            fee_rate_update_tx,
            native_currency_id,
            relay_chain_currency_id,
            wrapped_currency_id,
        };
        parachain_rpc.refresh_nonce().await;
        // TODO: refresh on registration
        parachain_rpc.store_assets_metadata().await?;
        Ok(parachain_rpc)
    }

    #[cfg(feature = "testing-utils")]
    pub async fn manual_seal(&self) {
        // rather than adding a conditional dependency on substrate, just re-define the
        // struct. We don't really care about the contents anyway, and if this is ever
        // to change upstream we'll know from failing tests
        #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
        pub struct ImportedAux {
            /// Only the header has been imported. Block body verification was skipped.
            pub header_only: bool,
            /// Clear all pending justification requests.
            pub clear_justification_requests: bool,
            /// Request a justification for the given block.
            pub needs_justification: bool,
            /// Received a bad justification.
            pub bad_justification: bool,
            /// Whether the block that was imported is the new best block.
            pub is_new_best: bool,
        }
        #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
        pub struct CreatedBlock<Hash> {
            /// hash of the created block.
            pub hash: Hash,
            /// some extra details about the import operation
            pub aux: ImportedAux,
        }

        let head = self.get_latest_block_hash().await.unwrap();
        let _: CreatedBlock<interbtc_runtime::Hash> = self
            .rpc()
            .request("engine_createBlock", rpc_params![true, true, head])
            .await
            .expect("failed to create block");
    }

    fn rpc(&self) -> Arc<RpcClient> {
        self.ext_client.rpc().client.clone()
    }

    pub async fn from_url(url: &str, signer: InterBtcSigner, shutdown_tx: ShutdownSender) -> Result<Self, Error> {
        let ws_client = new_websocket_client(url, None, None).await?;
        Self::new(ws_client, signer, shutdown_tx).await
    }

    pub async fn from_url_with_retry(
        url: &str,
        signer: InterBtcSigner,
        connection_timeout: Duration,
        shutdown_tx: ShutdownSender,
    ) -> Result<Self, Error> {
        Self::from_url_and_config_with_retry(url, signer, None, None, connection_timeout, shutdown_tx).await
    }

    pub async fn from_url_and_config_with_retry(
        url: &str,
        signer: InterBtcSigner,
        max_concurrent_requests: Option<usize>,
        max_notifs_per_subscription: Option<usize>,
        connection_timeout: Duration,
        shutdown_tx: ShutdownSender,
    ) -> Result<Self, Error> {
        let ws_client = new_websocket_client_with_retry(
            url,
            max_concurrent_requests,
            max_notifs_per_subscription,
            connection_timeout,
        )
        .await?;
        Self::new(ws_client, signer, shutdown_tx).await
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
            .account(&self.account_id, None)
            .await
            .map(|x| x.nonce)
            .unwrap_or(0);

        log::info!("Refreshing nonce: {}", account_info);
        signer.set_nonce(account_info);
    }

    /// Gets a copy of the signer with a unique nonce
    async fn with_unique_signer<'client, F, R>(
        &self,
        call: F,
    ) -> Result<TransactionEvents<'client, InterBtcRuntime, InterBtcEvent>, Error>
    where
        F: Fn(InterBtcSigner) -> R,
        R: Future<
            Output = Result<TransactionProgress<'client, InterBtcRuntime, DispatchError, InterBtcEvent>, BasicError>,
        >,
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
                match timeout(TRANSACTION_TIMEOUT, async {
                    if cfg!(feature = "testing-utils") {
                        call(signer).await?.wait_for_in_block().await?.wait_for_success().await
                    } else {
                        call(signer).await?.wait_for_finalized_success().await
                    }
                })
                .await
                {
                    Err(_) => {
                        log::warn!("Timeout on transaction submission - restart required");
                        let _ = self.shutdown_tx.send(Some(()));
                        Err(Error::Timeout)
                    }
                    Ok(x) => Ok(x?),
                }
            },
            |result| async {
                match result.map_err(Into::<Error>::into) {
                    Ok(te) => Ok(te),
                    Err(err) => {
                        if let Some(data) = err.is_invalid_transaction() {
                            self.refresh_nonce().await;
                            Err(RetryPolicy::Skip(Error::InvalidTransaction(data)))
                        } else if err.is_pool_too_low_priority().is_some() {
                            self.refresh_nonce().await;
                            Err(RetryPolicy::Skip(Error::PoolTooLowPriority))
                        } else if err.is_block_hash_not_found_error() {
                            self.refresh_nonce().await;
                            log::info!("Re-sending transaction after apparent fork");
                            Err(RetryPolicy::Skip(Error::BlockHashNotFound))
                        } else {
                            Err(RetryPolicy::Throw(err))
                        }
                    }
                }
            },
        )
        .await
    }

    pub async fn get_latest_block_hash(&self) -> Result<Option<H256>, Error> {
        if cfg!(feature = "testing-utils") {
            Ok(None)
        } else {
            Ok(Some(self.ext_client.rpc().finalized_head().await?))
        }
    }

    /// Subscribe to new parachain blocks.
    pub async fn on_block<F, R>(&self, on_block: F) -> Result<(), Error>
    where
        F: Fn(InterBtcHeader) -> R,
        R: Future<Output = Result<(), Error>>,
    {
        let mut sub = if cfg!(feature = "testing-utils") {
            self.ext_client.rpc().subscribe_blocks().await?
        } else {
            self.ext_client.rpc().subscribe_finalized_blocks().await?
        };
        loop {
            on_block(sub.next().await.ok_or(Error::ChannelClosed)??).await?;
        }
    }

    /// Wait for the block at the given height
    /// Note: will always wait at least one block.
    pub async fn wait_for_block(&self, height: u32) -> Result<(), Error> {
        let mut sub = if cfg!(feature = "testing-utils") {
            self.ext_client.rpc().subscribe_blocks().await?
        } else {
            self.ext_client.rpc().subscribe_finalized_blocks().await?
        };
        while let Some(block) = sub.next().await {
            if block?.number >= height {
                return Ok(());
            }
        }
        Err(Error::ChannelClosed)
    }

    /// Sleep for `delay` parachain blocks
    pub async fn delay_for_blocks(&self, delay: u32) -> Result<(), Error> {
        if delay == 0 {
            return Ok(());
        }
        let starting_parachain_height = self.get_current_chain_height().await?;
        self.wait_for_block(starting_parachain_height + delay).await
    }

    #[cfg(feature = "testing-utils")]
    async fn subscribe_events(
        &self,
    ) -> Result<
        subxt::events::EventSubscription<'_, subxt::events::EventSub<InterBtcHeader>, InterBtcRuntime, metadata::Event>,
        Error,
    > {
        Ok(self.api.events().subscribe().await?)
    }

    #[cfg(not(feature = "testing-utils"))]
    async fn subscribe_events(
        &self,
    ) -> Result<
        subxt::events::EventSubscription<
            '_,
            subxt::events::FinalizedEventSub<'_, InterBtcHeader>,
            InterBtcRuntime,
            metadata::Event,
        >,
        Error,
    > {
        Ok(self.api.events().subscribe_finalized().await?)
    }
    /// Subscription service that should listen forever, only returns if the initial subscription
    /// cannot be established. Calls `on_error` when an error event has been received, or when an
    /// event has been received that failed to be decoded into a raw event.
    ///
    /// # Arguments
    /// * `on_error` - callback for decoding errors, is not allowed to take too long
    pub async fn on_event_error<E: Fn(BasicError)>(&self, on_error: E) -> Result<(), Error> {
        let mut sub = self.subscribe_events().await?;

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
        let mut sub = self.subscribe_events().await?.filter_events::<(T,)>();
        let (tx, mut rx) = futures::channel::mpsc::channel::<T>(32);

        // two tasks: one for event listening and one for callback calling
        futures::future::try_join(
            async move {
                let tx = &tx;
                while let Some(result) = sub.next().fuse().await {
                    match result {
                        Ok(event_details) => {
                            let event = event_details.event;
                            log::trace!("event: {:?}", event);
                            if tx.clone().send(event).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => on_error(err.into()),
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
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// Emulate the POOL_INVALID_TX error using token transfer extrinsics.
    #[cfg(test)]
    pub async fn get_invalid_tx_error(&self, recipient: AccountId) -> Error {
        let mut signer = self.signer.write().await;

        self.api
            .tx()
            .tokens()
            .transfer(recipient.clone(), Token(DOT), 100)
            .sign_and_submit_then_watch_default(&signer.clone())
            .await
            .unwrap();

        signer.set_nonce(0);

        // now call with outdated nonce
        self.api
            .tx()
            .tokens()
            .transfer(recipient.clone(), Token(DOT), 100)
            .sign_and_submit_then_watch_default(&signer.clone())
            .await
            .unwrap_err()
            .into()
    }

    /// Emulate the POOL_TOO_LOW_PRIORITY error using token transfer extrinsics.
    #[cfg(test)]
    pub async fn get_too_low_priority_error(&self, recipient: AccountId) -> Error {
        let signer = self.signer.write().await;

        // submit tx but don't watch
        self.api
            .tx()
            .tokens()
            .transfer(recipient.clone(), Token(DOT), 100)
            .sign_and_submit_default(&signer.clone())
            .await
            .unwrap();

        // should call with the same nonce
        self.api
            .tx()
            .tokens()
            .transfer(recipient, Token(DOT), 100)
            .sign_and_submit_then_watch_default(&signer.clone())
            .await
            .unwrap_err()
            .into()
    }

    #[cfg(test)]
    pub async fn register_dummy_assets(&self) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            let metadatas = ["ABC", "TEst", "QQQ"].map(|symbol| GenericAssetMetadata {
                decimals: 10,
                location: None,
                name: b"irrelevant".to_vec(),
                symbol: symbol.as_bytes().to_vec(),
                existential_deposit: 0,
                additional: metadata::runtime_types::interbtc_primitives::CustomMetadata {
                    fee_per_second: 0,
                    coingecko_id: vec![],
                },
            });

            let registration_calls = metadatas
                .map(|metadata| {
                    EncodedCall::AssetRegistry(
                        metadata::runtime_types::orml_asset_registry::module::Call::register_asset {
                            metadata: metadata.clone(),
                            asset_id: None,
                        },
                    )
                })
                .to_vec();

            let batch = EncodedCall::Utility(metadata::runtime_types::pallet_utility::pallet::Call::batch {
                calls: registration_calls,
            });

            self.api
                .tx()
                .sudo()
                .sudo(batch)
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    pub async fn store_assets_metadata(&self) -> Result<(), Error> {
        AssetRegistry::extend(self.get_foreign_assets_metadata().await?)
    }

    /// Listen to fee_rate changes and broadcast new values on the fee_rate_update_tx channel
    pub async fn listen_for_fee_rate_changes(&self) -> Result<(), Error> {
        self.on_event::<FeedValuesEvent, _, _, _>(
            |event| async move {
                for (key, value) in event.values {
                    if let OracleKey::FeeEstimation = key {
                        let _ = self.fee_rate_update_tx.send(value);
                    }
                }
            },
            |_error| {
                // Don't propagate error, it's unlikely to be useful.
                // We assume critical errors will cause the system to restart.
                // Note that we can't send the error itself due to the channel requiring
                // the type to be clonable, which Error isn't
            },
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
pub trait UtilFuncs {
    /// Gets the current height of the parachain
    async fn get_current_chain_height(&self) -> Result<u32, Error>;

    async fn get_rpc_properties(&self) -> Result<serde_json::Map<String, Value>, Error>;

    /// Gets the ID of the native currency.
    fn get_native_currency_id(&self) -> CurrencyId;

    /// Get the address of the configured signer.
    fn get_account_id(&self) -> &AccountId;

    fn is_this_vault(&self, vault_id: &VaultId) -> bool;

    async fn get_foreign_assets_metadata(&self) -> Result<Vec<(u32, AssetMetadata)>, Error>;

    async fn get_foreign_asset_metadata(&self, id: u32) -> Result<AssetMetadata, Error>;
}

#[async_trait]
impl UtilFuncs for InterBtcParachain {
    async fn get_current_chain_height(&self) -> Result<u32, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().system().number(head).await?)
    }

    async fn get_rpc_properties(&self) -> Result<serde_json::Map<String, Value>, Error> {
        Ok(self.ext_client.rpc().system_properties().await?)
    }

    fn get_native_currency_id(&self) -> CurrencyId {
        self.native_currency_id
    }

    fn get_account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn is_this_vault(&self, vault_id: &VaultId) -> bool {
        &vault_id.account_id == self.get_account_id()
    }

    async fn get_foreign_assets_metadata(&self) -> Result<Vec<(u32, AssetMetadata)>, Error> {
        let head = self.get_latest_block_hash().await?;

        let mut ret = Vec::new();
        let mut metadata_iter = self.api.storage().asset_registry().metadata_iter(head).await?;
        while let Some((key, value)) = metadata_iter.next().await? {
            let raw_key = key.0.clone();

            // last bytes are the raw key
            let mut key = &raw_key[raw_key.len() - 4..];

            let decoded_key: u32 = Decode::decode(&mut key)?;
            ret.push((decoded_key, value));
        }
        Ok(ret)
    }

    async fn get_foreign_asset_metadata(&self, id: u32) -> Result<AssetMetadata, Error> {
        let head = self.get_latest_block_hash().await?;
        self.api
            .storage()
            .asset_registry()
            .metadata(&id, head)
            .await?
            .ok_or(Error::AssetNotFound)
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
            .accounts(&id, &currency_id, head)
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
            .accounts(&id, &currency_id, head)
            .await?
            .reserved)
    }

    async fn transfer_to(&self, recipient: &AccountId, amount: u128, currency_id: CurrencyId) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .tokens()
                .transfer(recipient.clone(), currency_id, amount)
                .sign_and_submit_then_watch_default(&signer)
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
    async fn request_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

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
    async fn request_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .replace()
                .request_replace(vault_id.currencies.clone(), amount)
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
            .rpc()
            .request("replace_getNewVaultReplaceRequests", rpc_params![account_id, head])
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
            .rpc()
            .request("replace_getOldVaultReplaceRequests", rpc_params![account_id, head])
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
            .replace_requests(&replace_id, head)
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

    fn on_fee_rate_change(&self) -> FeeRateUpdateReceiver;
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
            .aggregate(&OracleKey::ExchangeRate(currency_id), head)
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
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
            .aggregate(&OracleKey::FeeEstimation, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    /// Converts the amount in btc to dot, based on the current set exchange rate.
    async fn wrapped_to_collateral(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc()
            .request(
                "oracle_wrappedToCollateral",
                rpc_params![BalanceWrapper { amount }, currency_id, head],
            )
            .await?;

        Ok(result.amount)
    }

    /// Converts the amount in dot to btc, based on the current set exchange rate.
    async fn collateral_to_wrapped(&self, amount: u128, currency_id: CurrencyId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc()
            .request(
                "oracle_collateralToWrapped",
                rpc_params![BalanceWrapper { amount }, currency_id, head],
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
            .raw_values_updated(key, head)
            .await?
            .unwrap_or(false))
    }

    fn on_fee_rate_change(&self) -> FeeRateUpdateReceiver {
        self.fee_rate_update_tx.subscribe()
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
    async fn request_issue(&self, amount: u128, vault_id: &VaultId) -> Result<RequestIssueEvent, Error>;

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
    async fn request_issue(&self, amount: u128, vault_id: &VaultId) -> Result<RequestIssueEvent, Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .issue()
                .request_issue(amount, vault_id.clone())
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?
        .find_first::<RequestIssueEvent>()?
        .ok_or(Error::RequestIssueIDNotFound)
    }

    async fn execute_issue(&self, issue_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .issue()
                .execute_issue(issue_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
            .issue_requests(&issue_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_issue_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcIssueRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc()
            .request("issue_getVaultIssueRequests", rpc_params![account_id, head])
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
        let current_height = self.get_current_active_block_number().await?;
        let issue_period = self.get_issue_period().await?;

        let mut issue_requests = Vec::new();
        let head = self.get_latest_block_hash().await?;
        let mut iter = self.api.storage().issue().issue_requests_iter(head).await?;
        while let Some((issue_id, request)) = iter.next().await? {
            // todo: we also need to check the bitcoin height
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

    /// Get all redeem requests requested of the given vault
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
                    .sign_and_submit_then_watch_default(&signer)
                    .await
            })
            .await?
            .find_first::<RequestRedeemEvent>()?
            .ok_or(Error::RequestRedeemIDNotFound)?;
        Ok(redeem_event.redeem_id)
    }

    async fn execute_redeem(&self, redeem_id: H256, merkle_proof: &[u8], raw_tx: &[u8]) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .redeem()
                .execute_redeem(redeem_id, merkle_proof.into(), raw_tx.into())
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
            .redeem_requests(&redeem_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_redeem_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRedeemRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc()
            .request("redeem_getVaultRedeemRequests", rpc_params![account_id, head])
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

    /// Get all refund requests requested of the given vault
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
                .sign_and_submit_then_watch_default(&signer)
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
            .refund_requests(&refund_id, head)
            .await?
            .ok_or(Error::StorageItemNotFound)?)
    }

    async fn get_vault_refund_requests(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<(H256, InterBtcRefundRequest)>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Vec<H256> = self
            .rpc()
            .request("refund_getVaultRefundRequests", rpc_params![account_id, head])
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

    async fn initialize_btc_relay(&self, header: RawBlockHeader, height: BitcoinBlockHeight) -> Result<(), Error>;

    async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error>;

    async fn store_block_headers(&self, headers: Vec<RawBlockHeader>) -> Result<(), Error>;
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
        Ok(self.api.storage().btc_relay().chains_hashes(&0, &height, head).await?)
    }

    /// Get the corresponding block header for the given hash.
    ///
    /// # Arguments
    /// * `hash` - little endian block hash
    async fn get_block_header(&self, hash: H256Le) -> Result<InterBtcRichBlockHeader, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self.api.storage().btc_relay().block_headers(&hash, head).await?)
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
                        "block {} not found or confirmed, waiting for {:?}",
                        Into::<RichH256Le>::into(block_hash.clone()),
                        BLOCK_WAIT_TIMEOUT
                    );
                    sleep(BLOCK_WAIT_TIMEOUT).await;
                }
            };
        }
    }

    /// check that the block with the given block is included in the main chain of the relay, with sufficient
    /// confirmations
    async fn verify_block_header_inclusion(&self, block_hash: H256Le) -> Result<(), Error> {
        let head = self.get_latest_block_hash().await?;
        let result: Result<(), DispatchError> = self
            .rpc()
            .request(
                "btcRelay_verifyBlockHeaderInclusion",
                rpc_params![Into::<RichH256Le>::into(block_hash), head],
            )
            .await?;

        result.map_err(|err| Error::SubxtRuntimeError(SubxtError::Runtime(subxt::RuntimeError(err))))
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
                .btc_relay()
                .initialize(header.clone(), height)
                .sign_and_submit_then_watch_default(&signer)
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
                .btc_relay()
                .store_block_header(header.clone())
                .sign_and_submit_then_watch_default(&signer)
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
                    EncodedCall::BTCRelay(metadata::runtime_types::btc_relay::pallet::Call::store_block_header {
                        raw_block_header,
                    })
                })
                .collect(),
        )
        .await
    }
}

#[async_trait]
pub trait VaultRegistryPallet {
    async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, Error>;

    async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, Error>;

    async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, Error>;

    async fn register_vault(&self, vault_id: &VaultId, collateral: u128) -> Result<(), Error>;

    async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

    async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), Error>;

    async fn get_public_key(&self) -> Result<Option<BtcPublicKey>, Error>;

    async fn register_public_key(&self, public_key: BtcPublicKey) -> Result<(), Error>;

    async fn get_required_collateral_for_wrapped(
        &self,
        amount_btc: u128,
        collateral_currency: CurrencyId,
    ) -> Result<u128, Error>;

    async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, Error>;

    async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, Error>;

    async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, Error>;

    async fn set_current_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), Error>;

    async fn set_pending_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), Error>;
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
    async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, Error> {
        let head = self.get_latest_block_hash().await?;
        match self.api.storage().vault_registry().vaults(vault_id, head).await? {
            Some(InterBtcVault {
                status: VaultStatus::Liquidated,
                ..
            }) => Err(Error::VaultLiquidated),
            Some(vault) if &vault.id == vault_id => Ok(vault),
            _ => Err(Error::VaultNotFound),
        }
    }

    async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, Error> {
        let head = self.get_latest_block_hash().await?;
        let result = self
            .rpc()
            .request("vaultRegistry_getVaultsByAccountId", rpc_params![account_id, head])
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
    async fn register_vault(&self, vault_id: &VaultId, collateral: u128) -> Result<(), Error> {
        // TODO: check MinimumDeposit
        if collateral == 0 {
            return Err(Error::InsufficientFunds);
        }

        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .register_vault(vault_id.currencies.clone(), collateral)
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
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
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    async fn get_public_key(&self) -> Result<Option<BtcPublicKey>, Error> {
        let head = self.get_latest_block_hash().await?;
        Ok(self
            .api
            .storage()
            .vault_registry()
            .vault_bitcoin_public_key(self.get_account_id(), head)
            .await?)
    }

    /// Update the default BTC public key for the vault corresponding to the signer.
    ///
    /// # Arguments
    /// * `public_key` - the new public key of the vault
    async fn register_public_key(&self, public_key: BtcPublicKey) -> Result<(), Error> {
        let public_key = &public_key.clone();
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .register_public_key(public_key.clone())
                .sign_and_submit_then_watch_default(&signer)
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
            .rpc()
            .request(
                "vaultRegistry_getRequiredCollateralForWrapped",
                rpc_params![BalanceWrapper { amount: amount_btc }, collateral_currency, head],
            )
            .await?;

        Ok(result.amount)
    }

    /// Get the amount of collateral required for the given vault to be at the
    /// current SecureCollateralThreshold with the current exchange rate
    async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc()
            .request(
                "vaultRegistry_getRequiredCollateralForVault",
                rpc_params![vault_id, head],
            )
            .await?;

        Ok(result.amount)
    }

    async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: BalanceWrapper<_> = self
            .rpc()
            .request("vaultRegistry_getVaultTotalCollateral", rpc_params![vault_id, head])
            .await?;

        Ok(result.amount)
    }

    async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, Error> {
        let head = self.get_latest_block_hash().await?;
        let result: UnsignedFixedPoint = self
            .rpc()
            .request(
                "vaultRegistry_getCollateralizationFromVault",
                rpc_params![vault_id, only_issued, head],
            )
            .await?;

        Ok(result.into_inner())
    }

    /// For testing purposes only. Sets the current vault client release.
    ///
    /// # Arguments
    /// * `uri` - URI to the client release binary
    /// * `code_hash` - The runtime code hash associated with this client release
    async fn set_current_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .set_current_client_release(uri.to_vec(), *code_hash)
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?;
        Ok(())
    }

    /// For testing purposes only. Sets the pending vault client release.
    ///
    /// # Arguments
    /// * `uri` - URI to the client release binary
    /// * `code_hash` - The runtime code hash associated with this client release
    async fn set_pending_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), Error> {
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .vault_registry()
                .set_pending_client_release(uri.to_vec(), *code_hash)
                .sign_and_submit_then_watch_default(&signer)
                .await
        })
        .await?;
        Ok(())
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

#[cfg(any(
    feature = "parachain-metadata-interlay-testnet",
    feature = "parachain-metadata-kintsugi-testnet"
))]
#[async_trait]
impl SudoPallet for InterBtcParachain {
    async fn sudo(&self, call: EncodedCall) -> Result<(), Error> {
        let call = &call;
        self.with_unique_signer(|signer| async move {
            self.api
                .tx()
                .sudo()
                .sudo(call.clone())
                .sign_and_submit_then_watch_default(&signer)
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
        self.set_storage(crate::BTC_RELAY_MODULE, crate::STABLE_PARACHAIN_CONFIRMATIONS, value)
            .await
    }

    /// Set the global security parameter k for stable Bitcoin transactions
    async fn set_bitcoin_confirmations(&self, value: u32) -> Result<(), Error> {
        self.set_storage(crate::BTC_RELAY_MODULE, crate::STABLE_BITCOIN_CONFIRMATIONS, value)
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
