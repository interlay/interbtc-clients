use async_trait::async_trait;
use jsonrpsee::{
    common::{to_value as to_json_value, Params},
    Client as RpcClient,
};
use parity_scale_codec::Decode;
use sp_core::crypto::{AccountId32, Pair};
use sp_core::sr25519::Pair as KeyPair;
use sp_core::U256;
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::future::Future;
use std::sync::Arc;
use substrate_subxt::Error as XtError;
use substrate_subxt::{
    system::System, Client, ClientBuilder, EventSubscription, EventsDecoder, PairSigner,
};
use tokio::sync::RwLock;

use crate::btc_relay::*;
use crate::exchange_rate_oracle::*;
use crate::issue::*;
<<<<<<< HEAD
use crate::redeem::*;
=======
>>>>>>> bfd83e4... add u128 type
use crate::security::*;
use crate::staked_relayers::*;
use crate::timestamp::*;
use crate::vault_registry::*;
use crate::Error;
use crate::PolkaBtcRuntime;

pub type AccountId = <PolkaBtcRuntime as System>::AccountId;

pub type PolkaBtcVault = Vault<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as VaultRegistry>::PolkaBTC,
>;

pub type PolkaBtcStatusUpdate = StatusUpdate<
    AccountId,
    <PolkaBtcRuntime as System>::BlockNumber,
    <PolkaBtcRuntime as StakedRelayers>::DOT,
>;

#[derive(Clone)]
pub struct PolkaBtcProvider {
    rpc_client: RpcClient,
    ext_client: Client<PolkaBtcRuntime>,
    signer: Arc<RwLock<PairSigner<PolkaBtcRuntime, KeyPair>>>,
}

impl PolkaBtcProvider {
    pub async fn new<P: Into<jsonrpsee::Client>>(
        rpc_client: P,
        signer: Arc<RwLock<PairSigner<PolkaBtcRuntime, KeyPair>>>,
    ) -> Result<Self, Error> {
        let rpc_client = rpc_client.into();
        let ext_client = ClientBuilder::<PolkaBtcRuntime>::new()
            .set_client(rpc_client.clone())
            .build()
            .await?;

        // there is a race condition on signing
        // since we run the relayer in the background
        Ok(Self {
            rpc_client,
            ext_client,
            signer,
        })
    }

    pub async fn from_url(
        url: String,
        signer: Arc<RwLock<PairSigner<PolkaBtcRuntime, KeyPair>>>,
    ) -> Result<Self, Error> {
        let rpc_client = if url.starts_with("ws://") || url.starts_with("wss://") {
            jsonrpsee::ws_client(&url).await?
        } else {
            jsonrpsee::http_client(&url)
        };

        Self::new(rpc_client, signer).await
    }

    /// Get the address of the configured signer.
    pub async fn get_address(&self) -> AccountId32 {
        self.signer.read().await.signer().public().into()
    }

    /// Get the hash of the current best tip.
    pub async fn get_best_block(&self) -> Result<H256Le, Error> {
        Ok(self.ext_client.best_block(None).await?)
    }

    /// Get the current best known height.
    pub async fn get_best_block_height(&self) -> Result<u32, Error> {
        Ok(self.ext_client.best_block_height(None).await?)
    }

    /// Get the block hash for the main chain at the specified height.
    ///
    /// # Arguments
    /// * `height` - chain height
    pub async fn get_block_hash(&self, height: u32) -> Result<H256Le, Error> {
        // TODO: adjust chain index
        Ok(self.ext_client.chains_hashes(0, height, None).await?)
    }

    /// Get the corresponding block header for the given hash.
    ///
    /// # Arguments
    /// * `hash` - little endian block hash
    pub async fn get_block_header(&self, hash: H256Le) -> Result<RichBlockHeader, Error> {
        Ok(self.ext_client.block_headers(hash, None).await?)
    }

    /// Fetch a specific vault by ID.
    ///
    /// # Arguments
    /// * `vault_id` - account ID of the vault
    pub async fn get_vault(
        &self,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
    ) -> Result<PolkaBtcVault, Error> {
        Ok(self.ext_client.vaults(vault_id, None).await?)
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

    /// Initializes the relay with the provided block header and height,
    /// should be called automatically by `relayer_core` subject to the
    /// result of `is_initialized`.
    ///
    /// # Arguments
    /// * `header` - raw block header
    /// * `height` - starting height
    pub async fn initialize_btc_relay(
        &self,
        header: RawBlockHeader,
        height: BitcoinBlockHeight,
    ) -> Result<(), Error> {
        // TODO: can we initialize the relay through the chain-spec?
        // we would also need to consider re-initialization per governance
        self.ext_client
            .initialize_and_watch(&*self.signer.write().await, header, height)
            .await?;
        Ok(())
    }

    /// Stores a block header in the BTC-Relay.
    ///
    /// # Arguments
    /// * `header` - raw block header
    pub async fn store_block_header(&self, header: RawBlockHeader) -> Result<(), Error> {
        self.ext_client
            .store_block_header_and_watch(&*self.signer.write().await, header)
            .await?;
        Ok(())
    }

    /// Submit extrinsic to register a vault.
    ///
    /// # Arguments
    /// * `collateral` - deposit
    /// * `btc_address` - Bitcoin address hash
    pub async fn register_vault(&self, collateral: u128, btc_address: H160) -> Result<(), Error> {
        self.ext_client
            .register_vault_and_watch(&*self.signer.write().await, collateral, btc_address)
            .await?;
        Ok(())
    }

    /// Subscription service that listens for status updates.
    ///
    /// # Arguments
    /// * `on_proposal` - callback for suggested status updates
    /// * `on_error` - callback for errors
    pub async fn on_status_update_suggested<F, R, E>(
        &self,
        on_proposal: F,
        on_error: E,
    ) -> Result<(), Error>
    where
        F: Fn(StatusUpdateSuggestedEvent<PolkaBtcRuntime>) -> R,
        R: Future<Output = ()>,
        E: Fn(XtError),
    {
        let sub = self.ext_client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone());
        decoder.register_type_size::<u128>("Balance");
        decoder.register_type_size::<U256>("U256");
        decoder.register_type_size::<StatusCode>("StatusCode");
        decoder.register_type_size::<ErrorCode>("ErrorCode");
        decoder.register_type_size::<H256Le>("H256Le");

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, decoder);
        sub.filter_event::<StatusUpdateSuggestedEvent<_>>();
        while let Some(result) = sub.next().await {
            match result {
                Ok(raw_event) => {
                    let event = StatusUpdateSuggestedEvent::<PolkaBtcRuntime>::decode(
                        &mut &raw_event.data[..],
                    )?;

                    on_proposal(event).await;
                }
                Err(err) => on_error(err),
            };
        }

        Ok(())
    }

    /// Subscription service that should listen forever, only returns
    /// if the initial subscription cannot be established.
    ///
    /// # Arguments
    /// * `on_vault` - callback for newly registered vaults
    /// * `on_error` - callback for errors
    pub async fn on_register<F, R, E>(&self, mut on_vault: F, on_error: E) -> Result<(), Error>
    where
        F: FnMut(PolkaBtcVault) -> R,
        R: Future<Output = ()>,
        E: Fn(XtError),
    {
        let sub = self.ext_client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone());
        decoder.register_type_size::<u128>("Balance");
        decoder.register_type_size::<u128>("DOT");
        decoder.register_type_size::<H256Le>("H256Le");

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, decoder);
        sub.filter_event::<RegisterVaultEvent<_>>();
        while let Some(result) = sub.next().await {
            match result {
                Ok(raw_event) => {
                    // TODO: handle errors here
                    let event =
                        RegisterVaultEvent::<PolkaBtcRuntime>::decode(&mut &raw_event.data[..])?;
                    let account = self.ext_client.vaults(event.account_id, None).await?;
                    on_vault(account).await;
                }
                Err(err) => on_error(err),
            };
        }

        Ok(())
    }

    /// Subscription service that should listen forever, only returns
    /// if the initial subscription cannot be established.
    ///
    /// # Arguments
    /// * `on_block` - callback for newly stored blocks
    /// * `on_error` - callback for errors
    pub async fn on_store_block<F, E>(
        &self,
        on_block: impl Fn(u32, H256Le) -> F,
        on_error: E,
    ) -> Result<(), Error>
    where
        F: Future<Output = ()>,
        E: Fn(XtError),
    {
        let sub = self.ext_client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone());
        decoder.register_type_size::<H256Le>("H256Le");
        decoder.register_type_size::<StatusCode>("StatusCode");
        decoder.register_type_size::<ErrorCode>("ErrorCode");

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, decoder);
        sub.filter_event::<StoreMainChainHeaderEvent<_>>();
        while let Some(result) = sub.next().await {
            match result {
                Ok(raw_event) => {
                    // TODO: handle errors here
                    let event = StoreMainChainHeaderEvent::<PolkaBtcRuntime>::decode(
                        &mut &raw_event.data[..],
                    )?;
                    on_block(event.block_height, event.block_header_hash).await;
                }
                Err(err) => on_error(err),
            };
        }

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
    pub async fn is_transaction_invalid(
        &self,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
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
    async fn get_exchange_rate_info(&self) -> Result<(u64, u64, u64), Error>;

    async fn set_exchange_rate_info(&self, btc_to_dot_rate: u128) -> Result<(), Error>;
}

#[async_trait]
impl ExchangeRateOraclePallet for PolkaBtcProvider {
    /// Returns the last exchange rate, the time at which it was set
    /// and the configured max delay.
    async fn get_exchange_rate_info(&self) -> Result<(u64, u64, u64), Error> {
        let get_rate = self.ext_client.exchange_rate(None);
        let get_time = self.ext_client.last_exchange_rate_time(None);
        let get_delay = self.ext_client.max_delay(None);

        match tokio::try_join!(get_rate, get_time, get_delay) {
            Ok((rate, time, delay)) => Ok((rate.try_into()?, time.into(), delay.into())),
            Err(_) => Err(Error::ExchangeRateInfo),
        }
    }

    /// Sets the current exchange rate as BTC/DOT
    ///
    /// # Arguments
    /// * `btc_to_dot_rate` - the current BTC to DOT exchange rate encoded with the GRANULARITY
    async fn set_exchange_rate_info(&self, btc_to_dot_rate: u128) -> Result<(), Error> {
        self.ext_client
            .set_exchange_rate_and_watch(&*self.signer.lock().await, btc_to_dot_rate)
            .await?;
        Ok(())
    }
}

#[async_trait]
pub trait StakedRelayerPallet {
    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error>;

    async fn deregister_staked_relayer(&self) -> Result<(), Error>;

    async fn suggest_status_update(
        &self,
        deposit: u128,
        status_code: StatusCode,
        add_error: Option<ErrorCode>,
        remove_error: Option<ErrorCode>,
        block_hash: Option<H256Le>,
    ) -> Result<(), Error>;

    async fn vote_on_status_update(
        &self,
        status_update_id: U256,
        approve: bool,
    ) -> Result<(), Error>;

    async fn get_status_update(&self, id: u64) -> Result<PolkaBtcStatusUpdate, Error>;

    async fn report_oracle_offline(&self) -> Result<(), Error>;

    async fn report_vault_theft(
        &self,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;
}

#[async_trait]
impl StakedRelayerPallet for PolkaBtcProvider {
    /// Submit extrinsic to register the staked relayer.
    ///
    /// # Arguments
    /// * `stake` - deposit
    async fn register_staked_relayer(&self, stake: u128) -> Result<(), Error> {
        self.ext_client
            .register_staked_relayer_and_watch(&*self.signer.write().await, stake)
            .await?;
        Ok(())
    }

    /// Submit extrinsic to deregister the staked relayer.
    async fn deregister_staked_relayer(&self) -> Result<(), Error> {
        self.ext_client
            .deregister_staked_relayer_and_watch(&*self.signer.write().await)
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
    ) -> Result<(), Error> {
        self.ext_client
            .suggest_status_update_and_watch(
                &*self.signer.write().await,
                deposit,
                status_code,
                add_error,
                remove_error,
                block_hash,
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
        status_update_id: U256,
        approve: bool,
    ) -> Result<(), Error> {
        self.ext_client
            .vote_on_status_update_and_watch(&*self.signer.write().await, status_update_id, approve)
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
            .status_updates(status_update_id.into(), None)
            .await?)
    }

    /// Submit extrinsic to report that the oracle is offline.
    async fn report_oracle_offline(&self) -> Result<(), Error> {
        self.ext_client
            .report_oracle_offline_and_watch(&*self.signer.write().await)
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
        vault_id: <PolkaBtcRuntime as System>::AccountId,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.ext_client
            .report_vault_theft_and_watch(
                &*self.signer.write().await,
                vault_id,
                tx_id,
                tx_block_height,
                merkle_proof,
                raw_tx,
            )
            .await?;
        Ok(())
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
        vault_id: <PolkaBtcRuntime as System>::AccountId,
        griefing_collateral: u128,
<<<<<<< HEAD
    ) -> Result<H256, Error>;
=======
    ) -> Result<(), Error>;
>>>>>>> bfd83e4... add u128 type

    /// Execute a issue request by providing a Bitcoin transaction inclusion proof
    async fn execute_issue(
        &self,
        issue_id: H256,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    /// Cancel an ongoing issue request
    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error>;
}

#[async_trait]
impl IssuePallet for PolkaBtcProvider {
    async fn request_issue(
        &self,
        amount: u128,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
        griefing_collateral: u128,
<<<<<<< HEAD
    ) -> Result<H256, Error> {
        let sub = self.ext_client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone());
        // decoder.register_type_size::<u128>("Balance");
        // decoder.register_type_size::<u128>("DOT");

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, decoder);
        sub.filter_event::<RequestIssueEvent<_>>();
=======
    ) -> Result<(), Error> {
>>>>>>> bfd83e4... add u128 type
        self.ext_client
            .request_issue_and_watch(
                &*self.signer.lock().await,
                amount,
                vault_id,
                griefing_collateral,
            )
            .await?;
<<<<<<< HEAD
        let raw_event = sub.next().await.unwrap().unwrap();
        let event = RequestIssueEvent::<PolkaBtcRuntime>::decode(&mut &raw_event.data[..]);
        if let Ok(e) = event {
            println!("Requested to issue PolkaBTC with ID: {:?}", e.issue_id);
            Ok(e.issue_id)
        } else {
            Err(Error::RequestIssueIDNotFound)
        }
=======
        Ok(())
>>>>>>> bfd83e4... add u128 type
    }

    async fn execute_issue(
        &self,
        issue_id: H256,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.ext_client
            .execute_issue_and_watch(
                &*self.signer.lock().await,
                issue_id,
                tx_id,
                tx_block_height,
                merkle_proof,
                raw_tx,
            )
            .await?;
<<<<<<< HEAD
        Ok(())
    }

    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error> {
        self.ext_client
            .cancel_issue_and_watch(&*self.signer.lock().await, issue_id)
            .await?;
        Ok(())
    }
}

#[async_trait]
pub trait RedeemPallet {
    /// Request a new redeem
    async fn request_redeem(
        &self,
        amount_polka_btc: u128,
        btc_address: H160,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
    ) -> Result<H256, Error>;

    /// Execute a redeem request by providing a Bitcoin transaction inclusion proof
    async fn execute_redeem(
        &self,
        redeem_id: H256,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error>;

    /// Cancel an ongoing redeem request
    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error>;
}

#[async_trait]
impl RedeemPallet for PolkaBtcProvider {
    async fn request_redeem(
        &self,
        amount_polka_btc: u128,
        btc_address: H160,
        vault_id: <PolkaBtcRuntime as System>::AccountId,
    ) -> Result<H256, Error> {
        let sub = self.ext_client.subscribe_events().await?;
        let mut decoder = EventsDecoder::<PolkaBtcRuntime>::new(self.ext_client.metadata().clone());
        // decoder.register_type_size::<u128>("Balance");
        // decoder.register_type_size::<u128>("DOT");

        let mut sub = EventSubscription::<PolkaBtcRuntime>::new(sub, decoder);
        sub.filter_event::<RequestRedeemEvent<_>>();
        self.ext_client
            .request_redeem_and_watch(
                &*self.signer.lock().await,
                amount_polka_btc,
                btc_address,
                vault_id,
            )
            .await?;
        let raw_event = sub.next().await.unwrap().unwrap();
        let event = RequestRedeemEvent::<PolkaBtcRuntime>::decode(&mut &raw_event.data[..]);
        if let Ok(e) = event {
            println!("Requested to redeem PolkaBTC with ID: {:?}", e.redeem_id);
            Ok(e.redeem_id)
        } else {
            Err(Error::RequestRedeemIDNotFound)
        }
    }

    async fn execute_redeem(
        &self,
        redeem_id: H256,
        tx_id: H256Le,
        tx_block_height: u32,
        merkle_proof: Vec<u8>,
        raw_tx: Vec<u8>,
    ) -> Result<(), Error> {
        self.ext_client
            .execute_redeem_and_watch(
                &*self.signer.lock().await,
                redeem_id,
                tx_id,
                tx_block_height,
                merkle_proof,
                raw_tx,
            )
            .await?;
        Ok(())
    }

    async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), Error> {
        self.ext_client
            .cancel_redeem_and_watch(&*self.signer.lock().await, redeem_id, reimburse)
=======
        Ok(())
    }

    async fn cancel_issue(&self, issue_id: H256) -> Result<(), Error> {
        self.ext_client
            .cancel_issue_and_watch(&*self.signer.lock().await, issue_id)
>>>>>>> bfd83e4... add u128 type
            .await?;
        Ok(())
    }
}
