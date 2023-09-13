#![feature(int_roundings)]
#![feature(option_result_contains)]

pub mod cli;
pub mod light;

pub use light::{BitcoinLight, Error as BitcoinLightError};

mod addr;
mod electrs;
mod error;
mod iter;

use async_trait::async_trait;
use backoff::{backoff::Backoff, future::retry, ExponentialBackoff};
pub use bitcoincore_rpc::{
    bitcoin as bitcoin_primitives,
    bitcoin::{
        absolute::LockTime,
        address,
        address::Payload,
        block::Header as BlockHeader,
        blockdata::{opcodes::all as opcodes, script::Builder},
        consensus,
        consensus::encode::{deserialize, serialize},
        ecdsa::Signature as EcdsaSig,
        hash_types::{BlockHash, TxMerkleNode, WPubkeyHash},
        hashes::{self, hex::FromHex, sha256, Hash},
        key,
        merkle_tree::PartialMerkleTree,
        psbt, secp256k1,
        secp256k1::{constants::PUBLIC_KEY_SIZE, SecretKey},
        sighash::NonStandardSighashType,
        util::{self},
        Address, Amount, Block, Network, OutPoint, PrivateKey, PubkeyHash, PublicKey, Script, ScriptHash, SignedAmount,
        Transaction, TxIn, TxOut, Txid, VarInt, WScriptHash,
    },
    bitcoincore_rpc_json::{
        CreateRawTransactionInput, FundRawTransactionOptions, GetBlockchainInfoResult, GetRawTransactionResult,
        GetTransactionResult, GetTransactionResultDetailCategory, WalletTxInfo,
    },
    json::{self, AddressType, GetBlockResult},
    jsonrpc::{self, error::RpcError, Error as JsonRpcError},
    Auth, Client, Error as BitcoinError, RpcApi,
};
use bitcoincore_rpc::{bitcoin::consensus::encode::serialize_hex, bitcoincore_rpc_json::ScanningDetails};
pub use electrs::{ElectrsClient, Error as ElectrsError};
pub use error::{BitcoinRpcError, ConversionError, Error};
pub use iter::{reverse_stream_transactions, stream_blocks, stream_in_chain_transactions};
use log::{info, trace, warn};
use serde_json::error::Category as SerdeJsonCategory;
pub use sp_core::H256;
use std::{
    convert::TryInto,
    future::Future,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    time::{sleep, timeout},
};

#[macro_use]
extern crate num_derive;

/// timeout on the jsonrpc transport. jsonrpc default is 15 seconds.
pub const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(15);

/// Average time to mine a Bitcoin block.
pub const BLOCK_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes
pub const DEFAULT_MAX_TX_COUNT: usize = 100_000_000;
/// the bitcoin core version.
/// See https://github.com/bitcoin/bitcoin/blob/833add0f48b0fad84d7b8cf9373a349e7aef20b4/src/rpc/net.cpp#L627
/// and https://github.com/bitcoin/bitcoin/blob/833add0f48b0fad84d7b8cf9373a349e7aef20b4/src/clientversion.h#L33-L37
pub const BITCOIN_CORE_VERSION_23: usize = 230_000;
const NOT_IN_MEMPOOL_ERROR_CODE: i32 = BitcoinRpcError::RpcInvalidAddressOrKey as i32;

// Time to sleep before retry on startup.
const RETRY_DURATION: Duration = Duration::from_millis(1000);

// Time to sleep before checking if the rescan is done yet.
const RESCAN_POLL_INTERVAL: Duration = Duration::from_secs(10);

// The default initial interval value (1 second).
const INITIAL_INTERVAL: Duration = Duration::from_millis(1000);

// The default maximum elapsed time (24 hours).
const MAX_ELAPSED_TIME: Duration = Duration::from_secs(24 * 60 * 60);

// The default maximum back off time (5 minutes).
const MAX_INTERVAL: Duration = Duration::from_secs(5 * 60);

// The default multiplier value (delay doubles every time).
const MULTIPLIER: f64 = 2.0;

// Random value between 25% below and 25% above the ideal delay.
const RANDOMIZATION_FACTOR: f64 = 0.25;

const DERIVATION_KEY_LABEL: &str = "derivation-key";
const DEPOSIT_LABEL: &str = "deposit";

const SWEEP_ADDRESS: &str = "sweep-address";

fn get_exponential_backoff() -> ExponentialBackoff {
    ExponentialBackoff {
        current_interval: INITIAL_INTERVAL,
        initial_interval: INITIAL_INTERVAL,
        max_elapsed_time: Some(MAX_ELAPSED_TIME),
        max_interval: MAX_INTERVAL,
        multiplier: MULTIPLIER,
        randomization_factor: RANDOMIZATION_FACTOR,
        ..Default::default()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Clone, Debug)]
pub struct RawTransactionProof {
    pub user_tx_proof: Vec<u8>,
    pub raw_user_tx: Vec<u8>,
    pub coinbase_tx_proof: Vec<u8>,
    pub raw_coinbase_tx: Vec<u8>,
}

#[derive(PartialEq, Eq, PartialOrd, Clone, Copy, Debug)]
pub struct SatPerVbyte(pub u64);

#[derive(Debug, Clone)]
pub struct TransactionMetadata {
    pub txid: Txid,
    pub proof: RawTransactionProof,
    pub block_hash: BlockHash,
    pub fee: Option<SignedAmount>,
}

#[async_trait]
pub trait BitcoinCoreApi {
    fn is_full_node(&self) -> bool {
        true
    }

    fn network(&self) -> Network;

    async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, Error>;

    async fn get_block_count(&self) -> Result<u64, Error>;

    fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error>;

    fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, Error>;

    fn list_addresses(&self) -> Result<Vec<Address>, Error>;

    async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, Error>;

    async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error>;

    async fn get_new_address(&self) -> Result<Address, Error>;

    async fn get_new_sweep_address(&self) -> Result<Address, Error>;

    async fn get_last_sweep_height(&self) -> Result<Option<u32>, Error>;

    async fn get_new_public_key(&self) -> Result<PublicKey, Error>;

    fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, Error>;

    fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), Error>;

    async fn add_new_deposit_key(&self, public_key: PublicKey, secret_key: Vec<u8>) -> Result<(), Error>;

    async fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

    async fn get_pruned_height(&self) -> Result<u64, Error>;

    async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error>;

    async fn get_mempool_transactions<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + Send + 'a>, Error>;

    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        num_confirmations: u32,
        block_hash: Option<BlockHash>,
        is_wallet: bool,
    ) -> Result<TransactionMetadata, Error>;

    async fn bump_fee(&self, txid: &Txid, address: Address, fee_rate: SatPerVbyte) -> Result<Txid, Error>;

    async fn create_and_send_transaction(
        &self,
        address: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<Txid, Error>;

    async fn send_to_address(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
        fee_rate: SatPerVbyte,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    async fn sweep_funds(&self, address: Address) -> Result<Txid, Error>;

    async fn create_or_load_wallet(&self) -> Result<(), Error>;

    async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), Error>;

    async fn rescan_electrs_for_addresses(&self, addresses: Vec<Address>) -> Result<(), Error>;

    fn get_utxo_count(&self) -> Result<usize, Error>;

    async fn is_in_mempool(&self, txid: Txid) -> Result<bool, Error>;

    async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, Error>;

    async fn get_tx_for_op_return(&self, address: Address, amount: u128, data: H256) -> Result<Option<Txid>, Error>;
}

pub struct LockedTransaction {
    pub transaction: Transaction,
    recipient: String,
    _lock: Option<OwnedMutexGuard<()>>,
}

impl LockedTransaction {
    pub fn new(transaction: Transaction, recipient: String, lock: Option<OwnedMutexGuard<()>>) -> Self {
        LockedTransaction {
            transaction,
            recipient,
            _lock: lock,
        }
    }
}

struct ConnectionInfo {
    chain: Network,
    version: usize,
}

fn get_info(rpc: &Client) -> Result<ConnectionInfo, Error> {
    let blockchain_info = rpc.get_blockchain_info()?;
    let network_info = rpc.get_network_info()?;
    Ok(ConnectionInfo {
        chain: blockchain_info.chain,
        version: network_info.version,
    })
}

/// Connect to a bitcoin-core full node or timeout.
async fn connect(rpc: &Client, connection_timeout: Duration) -> Result<Network, Error> {
    info!("Connecting to bitcoin-core...");
    timeout(connection_timeout, async move {
        loop {
            match get_info(rpc) {
                Err(err)
                    if err.is_transport_error() =>
                {
                    trace!("A transport error occurred while attempting to communicate with bitcoin-core. Typically this indicates a failure to connect");
                    sleep(RETRY_DURATION).await;
                    continue;
                }
                Err(Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err))))
                    if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcInWarmup =>
                {
                    // may be loading block index or verifying wallet
                    trace!("bitcoin-core still in warm up");
                    sleep(RETRY_DURATION).await;
                    continue;
                }
                Err(Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Json(err)))) if err.classify() == SerdeJsonCategory::Syntax => {
                    // invalid response, can happen if server is in shutdown
                    trace!("bitcoin-core gave an invalid response: {}", err);
                    sleep(RETRY_DURATION).await;
                    continue;
                }
                Ok(ConnectionInfo{chain, version}) => {
                    info!("Connected to {}", chain);
                    info!("Bitcoin version {}", version);

                    if version >= BITCOIN_CORE_VERSION_23 {
                        return Err(Error::IncompatibleVersion(version))
                    }

                    return Ok(chain);
                }
                Err(err) => return Err(err),
            }
        }
    })
    .await?
}

pub struct BitcoinCoreBuilder {
    url: String,
    auth: Auth,
    wallet_name: Option<String>,
    electrs_url: Option<String>,
}

impl BitcoinCoreBuilder {
    pub fn new(url: String) -> Self {
        Self {
            url,
            auth: Auth::None,
            wallet_name: None,
            electrs_url: None,
        }
    }

    pub fn set_auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    pub fn set_wallet_name(mut self, wallet_name: Option<String>) -> Self {
        self.wallet_name = wallet_name;
        self
    }

    pub fn set_electrs_url(mut self, electrs_url: Option<String>) -> Self {
        self.electrs_url = electrs_url;
        self
    }

    fn new_client(&self) -> Result<Client, Error> {
        let url = match self.wallet_name {
            Some(ref x) => format!("{}/wallet/{}", self.url, x),
            None => self.url.clone(),
        };

        // construct a client with a known timeout - there is no way to query the default timeout
        let (user, pass) = self.auth.clone().get_user_pass()?;
        let mut transport_builder = jsonrpc::simple_http::Builder::new()
            .url(&url)
            .map_err(|e| bitcoincore_rpc::Error::JsonRpc(e.into()))?
            .timeout(TRANSPORT_TIMEOUT);

        if let Some(user) = user {
            transport_builder = transport_builder.auth(user, pass);
        }

        let rpc_client = jsonrpc::Client::with_transport(transport_builder.build());
        Ok(Client::from_jsonrpc(rpc_client))
    }

    pub fn build_with_network(self, network: Network) -> Result<BitcoinCore, Error> {
        BitcoinCore::new(self.new_client()?, self.wallet_name, network, self.electrs_url)
    }

    pub async fn build_and_connect(self, connection_timeout: Duration) -> Result<BitcoinCore, Error> {
        let client = self.new_client()?;
        let network = connect(&client, connection_timeout).await?;
        BitcoinCore::new(client, self.wallet_name, network, self.electrs_url)
    }
}

#[derive(Clone)]
pub struct BitcoinCore {
    pub rpc: Arc<Client>,
    wallet_name: Option<String>,
    network: Network,
    transaction_creation_lock: Arc<Mutex<()>>,
    electrs_client: ElectrsClient,
    #[cfg(feature = "regtest-manual-mining")]
    auto_mine: bool,
}

impl BitcoinCore {
    fn new(
        client: Client,
        wallet_name: Option<String>,
        network: Network,
        electrs_url: Option<String>,
    ) -> Result<Self, Error> {
        Ok(BitcoinCore {
            rpc: Arc::new(client),
            wallet_name,
            network,
            transaction_creation_lock: Arc::new(Mutex::new(())),
            electrs_client: ElectrsClient::new(electrs_url, network)?,
            #[cfg(feature = "regtest-manual-mining")]
            auto_mine: false,
        })
    }

    #[cfg(feature = "regtest-manual-mining")]
    pub fn set_auto_mining(&mut self, enable: bool) {
        self.auto_mine = enable;
    }

    /// Wait indefinitely for the node to sync.
    pub async fn sync(&self) -> Result<(), Error> {
        info!("Waiting for bitcoin-core to sync...");
        loop {
            let info = self.rpc.get_blockchain_info()?;
            // NOTE: initial_block_download is always true on regtest
            // but testnet and mainnet never reach 100% verification
            // Note that `initial_block_download` will return false before syncing is done.
            // When it's done downloading but still processing, `info.blocks` will be less than `info.headers`.
            if (!info.initial_block_download || info.verification_progress.eq(&1.0)) && info.blocks >= info.headers {
                info!("Synced!");
                return Ok(());
            }
            trace!("bitcoin-core not synced");
            sleep(RETRY_DURATION).await;
        }
    }

    /// Wrapper of rust_bitcoincore_rpc::create_raw_transaction_hex that accepts an optional op_return
    fn create_raw_transaction_hex(
        &self,
        address: String,
        amount: Amount,
        request_id: Option<H256>,
    ) -> Result<String, Error> {
        let mut outputs = serde_json::Map::<String, serde_json::Value>::new();
        // add the payment output
        outputs.insert(address, serde_json::Value::from(amount.to_btc()));

        if let Some(request_id) = request_id {
            // add the op_return data - bitcoind will add op_return and the length automatically
            outputs.insert("data".to_string(), serde_json::Value::from(hex::encode(request_id)));
        }

        let args = [
            serde_json::to_value::<&[json::CreateRawTransactionInput]>(&[])?,
            serde_json::to_value(outputs)?,
            serde_json::to_value(0i64)?, /* locktime - default 0: see https://developer.bitcoin.org/reference/rpc/createrawtransaction.html */
            serde_json::to_value(true)?, // BIP125-replaceable, aka Replace By Fee (RBF)
        ];
        Ok(self.rpc.call("createrawtransaction", &args)?)
    }

    async fn fund_and_sign_transaction(
        &self,
        fee_rate: SatPerVbyte,
        raw_tx: &str,
        return_to_self_address: &Option<Address>,
        recipient: &str,
        auto_retry: bool,
    ) -> Result<LockedTransaction, Error> {
        self.with_wallet_inner(auto_retry, || async {
            // ensure no other fund_raw_transaction calls are made until we submitted the
            // transaction to the bitcoind. If we don't do this, the same uxto may be used
            // as input twice (i.e. double spend)
            let lock = self.transaction_creation_lock.clone().lock_owned().await;
            // FundRawTransactionOptions takes an amount per kvByte, rather than per vByte
            let fee_rate = fee_rate.0.saturating_mul(1_000);
            let funding_opts = FundRawTransactionOptions {
                fee_rate: Some(Amount::from_sat(fee_rate)),
                change_address: return_to_self_address.clone(),
                replaceable: Some(true),
                ..Default::default()
            };

            // fund the transaction: adds required inputs, and possibly a return-to-self output
            let funded_raw_tx = self.rpc.fund_raw_transaction(raw_tx, Some(&funding_opts), None)?;

            // sign the transaction
            let signed_funded_raw_tx =
                self.rpc
                    .sign_raw_transaction_with_wallet(&funded_raw_tx.transaction()?, None, None)?;

            // Make sure signing is successful
            if signed_funded_raw_tx.errors.is_some() {
                log::warn!(
                    "Received bitcoin funding errors (complete={}): {:?}",
                    signed_funded_raw_tx.complete,
                    signed_funded_raw_tx.errors
                );
                return Err(Error::TransactionSigningError);
            }

            let transaction = signed_funded_raw_tx.transaction()?;

            Ok(LockedTransaction::new(transaction, recipient.to_string(), Some(lock)))
        })
        .await
    }

    /// Creates and return a transaction; it is not submitted to the mempool. While the returned value
    /// is alive, no other transactions can be created (this is guarded by a mutex). This prevents
    /// accidental double spending.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `fee_rate` - fee rate in sat/vbyte
    /// * `request_id` - the issue/redeem/replace id for which this transfer is being made
    async fn create_transaction(
        &self,
        address: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<LockedTransaction, Error> {
        let recipient = address.to_string();
        let raw_tx = self
            .with_wallet(|| async {
                // create raw transaction that includes the op_return (if any). If we were to add the op_return
                // after funding, the fees might be insufficient. An alternative to our own version of
                // this function would be to call create_raw_transaction (without the _hex suffix), and
                // to add the op_return afterwards. However, this function fails if no inputs are
                // specified, as is the case for us prior to calling fund_raw_transaction.
                self.create_raw_transaction_hex(recipient.clone(), Amount::from_sat(sat), request_id)
            })
            .await?;

        self.fund_and_sign_transaction(fee_rate, &raw_tx, &None, &recipient, true)
            .await
    }

    /// Submits a transaction to the mempool
    ///
    /// # Arguments
    /// * `transaction` - The transaction created by create_transaction
    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, Error> {
        log::info!("Sending bitcoin to {}", transaction.recipient);

        // place the transaction into the mempool, this is fine to retry
        let txid = self
            .with_wallet(|| async { Ok(self.rpc.send_raw_transaction(&transaction.transaction)?) })
            .await?;

        #[cfg(feature = "regtest-manual-mining")]
        if self.auto_mine {
            log::debug!("Auto-mining!");

            self.rpc.generate_to_address(
                1,
                &self
                    .rpc
                    .get_new_address(None, Some(AddressType::Bech32))?
                    .require_network(self.network)?,
            )?;
        }

        Ok(txid)
    }

    #[cfg(feature = "regtest-manual-mining")]
    pub fn mine_blocks(&self, block_num: u64, maybe_address: Option<Address>) -> BlockHash {
        let address = maybe_address.unwrap_or_else(|| {
            self.rpc
                .get_new_address(None, Some(AddressType::Bech32))
                .unwrap()
                .require_network(self.network)
                .unwrap()
        });
        self.rpc
            .generate_to_address(block_num, &address)
            .unwrap()
            .last()
            .unwrap()
            .clone()
    }

    async fn with_retry_on_timeout<F, R, T>(&self, call: F) -> Result<T, Error>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T, Error>>,
    {
        loop {
            let time = Instant::now();
            match call().await.map_err(Error::from) {
                Err(inner) if inner.is_transport_error() && time.elapsed() >= TRANSPORT_TIMEOUT => {
                    info!("Call timed out - retrying...");
                    // timeout - retry again
                }
                result => return result,
            };
        }
    }

    async fn with_wallet<F, R, T>(&self, call: F) -> Result<T, Error>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T, Error>>,
    {
        self.with_wallet_inner(true, call).await
    }

    /// Exactly like with_wallet, but with with opt-out of retrying wallet error
    async fn with_wallet_inner<F, R, T>(&self, retry_on_wallet_error: bool, call: F) -> Result<T, Error>
    where
        F: Fn() -> R,
        R: Future<Output = Result<T, Error>>,
    {
        let mut backoff = get_exponential_backoff();
        loop {
            let err = match call().await.map_err(Error::from) {
                Err(inner) if inner.is_wallet_not_found() => {
                    // wallet not loaded (e.g. daemon restarted)
                    self.create_or_load_wallet().await?;
                    inner
                }
                Err(inner) if retry_on_wallet_error && inner.is_wallet_error() => {
                    // fee estimation failed or other
                    inner
                }
                result => return result,
            };

            match backoff.next_backoff() {
                Some(wait) => {
                    // error occurred, sleep before retrying
                    log::warn!("{:?} - next retry in {:.3} s", err, wait.as_secs_f64());
                    tokio::time::sleep(wait).await;
                }
                None => break Err(Error::ConnectionRefused),
            }
        }
    }

    pub async fn wallet_has_public_key(&self, public_key: PublicKey) -> Result<bool, Error> {
        self.with_wallet(|| async {
            let address = Address::p2wpkh(&public_key, self.network).map_err(ConversionError::from)?;
            let address_info = self.rpc.get_address_info(&address)?;
            let wallet_pubkey = address_info.pubkey.ok_or(Error::MissingPublicKey)?;
            Ok(wallet_pubkey == public_key)
        })
        .await
    }

    pub async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), Error> {
        self.with_wallet(|| async { Ok(self.rpc.import_private_key(&privkey, None, None)?) })
            .await
    }

    pub async fn wait_for_rescan(&self) -> Result<(), Error> {
        loop {
            let wallet_info = self.rpc.get_wallet_info()?;
            match wallet_info.scanning {
                Some(ScanningDetails::Scanning { progress, .. }) => {
                    info!("Scanning progress: {progress}");
                    tokio::time::sleep(RESCAN_POLL_INTERVAL).await;
                }
                _ => return Ok(()),
            }
        }
    }
}

/// true if the given indicates that the item was not found in the mempool
fn err_not_in_mempool(err: &bitcoincore_rpc::Error) -> bool {
    matches!(
        err,
        &bitcoincore_rpc::Error::JsonRpc(JsonRpcError::Rpc(RpcError {
            code: NOT_IN_MEMPOOL_ERROR_CODE,
            ..
        }))
    )
}

#[async_trait]
impl BitcoinCoreApi for BitcoinCore {
    fn network(&self) -> Network {
        self.network
    }

    /// Wait for a specified height to return a `BlockHash` or
    /// exit on error.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    /// * `num_confirmations` - minimum for a block to be accepted
    async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, Error> {
        loop {
            match self.rpc.get_block_hash(height.into()) {
                Ok(hash) => {
                    let info = self.rpc.get_block_info(&hash)?;
                    if info.confirmations >= num_confirmations as i32 {
                        return Ok(self.rpc.get_block(&hash)?);
                    } else {
                        sleep(RETRY_DURATION).await;
                        continue;
                    }
                }
                Err(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                    if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcInvalidParameter =>
                {
                    // block does not exist yet
                    sleep(RETRY_DURATION).await;
                    continue;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// Get the tip of the main chain as reported by Bitcoin core.
    async fn get_block_count(&self) -> Result<u64, Error> {
        Ok(self.rpc.get_block_count()?)
    }

    /// Get wallet balance.
    fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error> {
        Ok(self
            .rpc
            .get_balance(min_confirmations.map(|x| x.try_into().unwrap_or_default()), None)?)
    }

    /// List the transaction in the wallet. `max_count` sets a limit on the amount of transactions returned.
    /// If none is provided, [`DEFAULT_MAX_TX_COUNT`] is used, which is an arbitrarily picked big number to
    /// effectively return all transactions.
    fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, Error> {
        // If no `max_count` is specified to the rpc call, bitcoin core only returns 10 items.
        Ok(self
            .rpc
            .list_transactions(None, max_count.or(Some(DEFAULT_MAX_TX_COUNT)), None, None)?)
    }

    // TODO: remove this once the wallet migration has completed
    fn list_addresses(&self) -> Result<Vec<Address>, Error> {
        // Lists groups of addresses which have had their common ownership
        // made public by common use as inputs or as the resulting change
        // in past transactions
        let groupings: Vec<Vec<Vec<serde_json::Value>>> = self.rpc.call("listaddressgroupings", &[])?;
        let addresses = groupings
            .into_iter()
            .flatten()
            .filter_map(|group| {
                group
                    .get(0)
                    .and_then(|v| v.as_str())
                    .map(Address::from_str)?
                    .and_then(|x| x.require_network(self.network))
                    .ok()
            })
            .collect::<Vec<_>>();
        Ok(addresses)
    }

    /// Get the raw transaction identified by `Txid` and stored
    /// in the specified block.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(&self.rpc.get_raw_transaction(txid, Some(block_hash))?))
    }

    /// Get the raw transaction identified by `Txid` and stored
    /// in the specified block.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, Error> {
        Ok(self.rpc.get_raw_transaction(txid, block_hash.as_ref())?)
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[txid], Some(block_hash))?)
    }

    /// Get the block hash for a given height.
    ///
    /// # Arguments
    /// * `height` - block height
    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error> {
        match self.rpc.get_block_hash(height.into()) {
            Ok(block_hash) => Ok(block_hash),
            Err(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcInvalidParameter =>
            {
                // block does not exist yet
                Err(Error::InvalidBitcoinHeight)
            }
            Err(err) => return Err(err.into()),
        }
    }

    /// Gets a new address from the wallet
    async fn get_new_address(&self) -> Result<Address, Error> {
        Ok(self
            .rpc
            .get_new_address(None, Some(AddressType::Bech32))?
            .require_network(self.network)?)
    }

    async fn get_new_sweep_address(&self) -> Result<Address, Error> {
        Ok(self
            .rpc
            .get_new_address(Some(SWEEP_ADDRESS), Some(AddressType::Bech32))?
            .require_network(self.network)?)
    }

    async fn get_last_sweep_height(&self) -> Result<Option<u32>, Error> {
        Ok(self
            .rpc
            .list_transactions(Some(SWEEP_ADDRESS), Some(DEFAULT_MAX_TX_COUNT), None, None)?
            .into_iter()
            // we want to return None if there is no sweep tx for full nodes or new
            // pruned nodes and we should return an error if any tx is still in the mempool
            .map(|tx| tx.info.blockheight.ok_or(Error::ConfirmationError))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .min())
    }

    /// Gets a new public key for an address in the wallet
    async fn get_new_public_key(&self) -> Result<PublicKey, Error> {
        let address = self
            .rpc
            .get_new_address(Some(DERIVATION_KEY_LABEL), Some(AddressType::Bech32))?
            .require_network(self.network)?;
        let address_info = self.rpc.get_address_info(&address)?;
        let public_key = address_info.pubkey.ok_or(Error::MissingPublicKey)?;
        Ok(public_key)
    }

    fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, Error> {
        Ok(self.rpc.dump_private_key(address)?)
    }

    fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), Error> {
        Ok(self.rpc.import_private_key(
            private_key,
            is_derivation_key.then_some(DERIVATION_KEY_LABEL),
            Some(false),
        )?)
    }

    /// Derive and import the private key for the master public key and public secret
    async fn add_new_deposit_key(&self, public_key: PublicKey, secret_key: Vec<u8>) -> Result<(), Error> {
        let address = Address::p2wpkh(&public_key, self.network).map_err(ConversionError::from)?;
        let private_key = self.rpc.dump_private_key(&address)?;
        let deposit_secret_key =
            addr::calculate_deposit_secret_key(private_key.inner, SecretKey::from_slice(&secret_key)?)?;
        self.rpc.import_private_key(
            &PrivateKey {
                compressed: private_key.compressed,
                network: self.network,
                inner: deposit_secret_key,
            },
            Some(DEPOSIT_LABEL),
            // rescan true by default
            Some(false),
        )?;
        Ok(())
    }

    async fn get_best_block_hash(&self) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_best_block_hash()?)
    }

    async fn get_pruned_height(&self) -> Result<u64, Error> {
        Ok(self.rpc.get_blockchain_info()?.prune_height.unwrap_or(0))
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        Ok(self.rpc.get_block(hash)?)
    }

    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error> {
        Ok(self.rpc.get_block_header(hash)?)
    }

    /// Get the transactions that are currently in the mempool. Since `impl trait` is not
    /// allowed within trait method, we have to use trait objects.
    async fn get_mempool_transactions<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + Send + 'a>, Error> {
        // get txids from the mempool
        let txids = self.rpc.get_raw_mempool()?;
        // map txid to the actual Transaction structs
        let iterator = txids.into_iter().filter_map(move |txid| {
            match self.rpc.get_raw_transaction(&txid, None) {
                Ok(x) => Some(Ok(x)),
                Err(e) if err_not_in_mempool(&e) => None, // not in mempool anymore, so filter out
                Err(e) => Some(Err(e.into())),            // unknown error, propagate to user
            }
        });
        Ok(Box::new(iterator))
    }

    /// Waits for the required number of confirmations, and collects data about the
    /// transaction
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `num_confirmations` - how many confirmations we need to wait for
    /// * `block_hash` - optional block hash
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        num_confirmations: u32,
        block_hash: Option<BlockHash>,
        is_wallet: bool,
    ) -> Result<TransactionMetadata, Error> {
        let (block_hash, fee) = retry(get_exponential_backoff(), || async {
            if is_wallet {
                Ok(match self.rpc.get_transaction(&txid, None) {
                    Ok(GetTransactionResult {
                        info:
                            WalletTxInfo {
                                confirmations,
                                blockhash: Some(hash),
                                ..
                            },
                        fee,
                        ..
                    }) if confirmations >= 0 && confirmations as u32 >= num_confirmations => Ok((hash, fee)),
                    Ok(_) => Err(Error::ConfirmationError),
                    Err(e) => {
                        log::error!("{}", e);
                        Err(e.into())
                    }
                }?)
            } else {
                Ok(match self.rpc.get_raw_transaction_info(&txid, block_hash.as_ref()) {
                    Ok(GetRawTransactionResult {
                        confirmations: Some(num),
                        blockhash: Some(hash),
                        ..
                    }) if num >= num_confirmations => Ok((hash, None)),
                    Ok(_) => Err(Error::ConfirmationError),
                    Err(e) => {
                        log::error!("{}", e);
                        Err(e.into())
                    }
                }?)
            }
        })
        .await?;

        let proof = retry(get_exponential_backoff(), || async {
            // fetch coinbase info..
            let block = self.get_block(&block_hash).await?;
            let coinbase_tx = block.coinbase().ok_or(Error::CoinbaseFetchingFailure)?;
            let coinbase_txid = coinbase_tx.txid();
            let coinbase_tx_proof = self.get_proof(coinbase_txid, &block_hash).await?;
            let raw_coinbase_tx = self.get_raw_tx(&coinbase_txid, &block_hash).await?;

            // fetch user tx info..
            let raw_user_tx = self.get_raw_tx(&txid, &block_hash).await?;
            let user_tx_proof = self.get_proof(txid, &block_hash).await?;

            Ok(RawTransactionProof {
                raw_coinbase_tx,
                coinbase_tx_proof,
                raw_user_tx,
                user_tx_proof,
            })
        })
        .await?;

        Ok(TransactionMetadata {
            txid,
            proof,
            block_hash,
            fee,
        })
    }

    async fn bump_fee(&self, txid: &Txid, address: Address, fee_rate: SatPerVbyte) -> Result<Txid, Error> {
        let (raw_tx, return_to_self_address) = self
            .with_wallet_inner(false, || async {
                let mut existing_transaction = self.rpc.get_raw_transaction(txid, None)?;

                let return_to_self = existing_transaction
                    .extract_return_to_self_address(&address.payload)?
                    .map(|(idx, payload)| {
                        existing_transaction.output.remove(idx);
                        Address::new(self.network(), payload)
                    });

                let raw_tx = serialize_hex(&existing_transaction);
                Ok((raw_tx, return_to_self))
            })
            .await?;

        let recipient = address.to_string();
        let tx = self
            .fund_and_sign_transaction(fee_rate, &raw_tx, &return_to_self_address, &recipient, false)
            .await?;

        let txid = self
            .with_wallet_inner(false, || async { Ok(self.rpc.send_raw_transaction(&tx.transaction)?) })
            .await?;

        #[cfg(feature = "regtest-manual-mining")]
        if self.auto_mine {
            log::debug!("Auto-mining!");

            self.rpc.generate_to_address(
                1,
                &self
                    .rpc
                    .get_new_address(None, Some(AddressType::Bech32))?
                    .require_network(self.network)?,
            )?;
        }

        Ok(txid)
    }

    /// Send an amount of Bitcoin to an address, but only submit the transaction
    /// to the mempool; this method does not wait until the block is included in
    /// the blockchain.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `fee_rate` - fee rate in sat/vbyte
    /// * `request_id` - the issue/redeem/replace id for which this transfer is being made
    async fn create_and_send_transaction(
        &self,
        address: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<Txid, Error> {
        let tx = self.create_transaction(address, sat, fee_rate, request_id).await?;
        let txid = self.send_transaction(tx).await?;
        Ok(txid)
    }

    /// Send an amount of Bitcoin to an address and wait until it is included
    /// in the blockchain with the requested number of confirmations.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `request_id` - the issue/redeem/replace id for which this transfer is being made
    /// * `fee_rate` - fee rate in sat/vbyte
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn send_to_address(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
        fee_rate: SatPerVbyte,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let txid = self
            .create_and_send_transaction(address, sat, fee_rate, request_id)
            .await?;

        Ok(self
            .wait_for_transaction_metadata(txid, num_confirmations, None, true)
            .await?)
    }

    async fn sweep_funds(&self, address: Address) -> Result<Txid, Error> {
        let unspent = self.rpc.list_unspent(None, None, None, None, None)?;

        let mut amount = Amount::ZERO;
        let mut utxos = Vec::<json::CreateRawTransactionInput>::new();

        for entry in unspent {
            if self.electrs_client.is_tx_output_spent(&entry.txid, entry.vout).await? {
                log::info!("{}:{} already spent", entry.txid, entry.vout);
                // skip if already spent
                continue;
            }
            amount += entry.amount;
            utxos.push(json::CreateRawTransactionInput {
                txid: entry.txid,
                vout: entry.vout,
                sequence: None,
            })
        }

        log::info!("Sweeping {} from {} utxos", amount, utxos.len());
        let mut outputs = serde_json::Map::<String, serde_json::Value>::new();
        outputs.insert(address.to_string(), serde_json::Value::from(amount.to_btc()));

        let args = [
            serde_json::to_value::<&[json::CreateRawTransactionInput]>(&utxos)?,
            serde_json::to_value(outputs)?,
            serde_json::to_value(0i64)?, /* locktime - default 0: see https://developer.bitcoin.org/reference/rpc/createrawtransaction.html */
            serde_json::to_value(true)?, // BIP125-replaceable, aka Replace By Fee (RBF)
        ];
        let raw_tx: String = self.rpc.call("createrawtransaction", &args)?;

        let funding_opts = FundRawTransactionOptions {
            fee_rate: None,
            add_inputs: Some(false),
            subtract_fee_from_outputs: Some(vec![0]),
            ..Default::default()
        };
        let funded_raw_tx = self.rpc.fund_raw_transaction(raw_tx, Some(&funding_opts), None)?;

        let signed_funded_raw_tx =
            self.rpc
                .sign_raw_transaction_with_wallet(&funded_raw_tx.transaction()?, None, None)?;

        if signed_funded_raw_tx.errors.is_some() {
            log::warn!(
                "Received bitcoin funding errors (complete={}): {:?}",
                signed_funded_raw_tx.complete,
                signed_funded_raw_tx.errors
            );
            return Err(Error::TransactionSigningError);
        }

        let transaction = signed_funded_raw_tx.transaction()?;
        let txid = self.rpc.send_raw_transaction(&transaction)?;
        log::info!("Sent sweep tx: {txid}");

        Ok(txid)
    }

    /// Create or load a wallet on Bitcoin Core.
    async fn create_or_load_wallet(&self) -> Result<(), Error> {
        let wallet_name = if let Some(ref wallet_name) = self.wallet_name {
            wallet_name
        } else {
            return Err(Error::WalletNotFound);
        };

        self.with_retry_on_timeout(|| async {
            if self.rpc.list_wallets()?.contains(wallet_name) {
                // already loaded - nothing to do
                info!("Wallet {wallet_name} already loaded");
            } else if self.rpc.list_wallet_dir()?.contains(wallet_name) {
                // wallet exists but is not loaded
                info!("Loading wallet {wallet_name}...");
                let result = self.rpc.load_wallet(wallet_name)?;
                if let Some(warning) = result.warning {
                    warn!("Received error while loading wallet {wallet_name}: {warning}");
                }
            } else {
                info!("Creating wallet {wallet_name}...");
                // wallet does not exist, create
                let result = self.rpc.create_wallet(wallet_name, None, None, None, None)?;
                if let Some(warning) = result.warning {
                    if !warning.is_empty() {
                        warn!("Received warning while creating wallet {wallet_name}: {warning}");
                    }
                }
            }
            Ok(())
        })
        .await
    }

    async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), Error> {
        // if there happens to be a rescan going on, we wait for it to finish and then
        // initiate our own rescan, since the range might be different and keys might just
        // have been imported
        self.wait_for_rescan().await?;

        match self
            .rpc
            .rescan_blockchain(Some(start_height), Some(end_height))
            .map(|_| ())
            .map_err(Into::<Error>::into)
        {
            Err(e) if e.is_transport_error() => {
                // we assume that if we get a transport error, it's because the
                // rescan timed out. We just wait for it to complete
                self.wait_for_rescan().await
            }
            x => x,
        }
    }

    async fn rescan_electrs_for_addresses(&self, addresses: Vec<Address>) -> Result<(), Error> {
        for address in addresses.into_iter() {
            let address = address.to_string();
            let all_transactions = self.electrs_client.get_address_tx_history_full(&address).await?;
            // filter to only import
            // a) payments in the blockchain (not in mempool), and
            // b) payments TO the address (as bitcoin core will already know about transactions spending FROM it)
            let confirmed_payments_to = all_transactions.iter().filter(|tx| {
                if let Some(status) = &tx.status {
                    if !status.confirmed {
                        return false;
                    }
                };
                tx.vout
                    .iter()
                    .any(|output| matches!(&output.scriptpubkey_address, Some(addr) if addr == &address))
            });
            for transaction in confirmed_payments_to {
                let (raw_tx, raw_merkle_proof) = futures::future::try_join(
                    self.electrs_client.get_tx_hex(&transaction.txid),
                    self.electrs_client.get_tx_merkle_block_proof(&transaction.txid),
                )
                .await?;
                self.rpc.call(
                    "importprunedfunds",
                    &[serde_json::to_value(raw_tx)?, serde_json::to_value(raw_merkle_proof)?],
                )?;
            }
        }
        Ok(())
    }

    /// Get the number of unspent transaction outputs.
    fn get_utxo_count(&self) -> Result<usize, Error> {
        Ok(self.rpc.list_unspent(None, None, None, None, None)?.len())
    }

    async fn is_in_mempool(&self, txid: Txid) -> Result<bool, Error> {
        let get_tx_result = self.rpc.get_transaction(&txid, None)?;
        Ok(get_tx_result.info.confirmations == 0)
    }

    async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, Error> {
        // unfortunately we need both of these rpc results. The result of the second call
        // is not a parsed tx, but rather a GetTransactionResult.
        let tx = self.rpc.get_raw_transaction(&txid, None)?;
        let get_tx_result = self.rpc.get_transaction(&txid, None)?;

        // to get from weight to vsize we divide by 4, but round up by first adding 3
        // Note that we can not rely on tx.get_size() since it doesn't 'discount' witness bytes
        let vsize = tx.weight().to_vbytes_ceil();

        let fee = get_tx_result
            .fee
            .ok_or(Error::MissingBitcoinFeeInfo)?
            .to_sat()
            .checked_abs()
            .ok_or(Error::ArithmeticError)?;

        log::debug!("fee: {fee}, size: {vsize}");

        let fee_rate = fee.checked_div(vsize.try_into()?).ok_or(Error::ArithmeticError)?;
        Ok(SatPerVbyte(fee_rate.try_into()?))
    }

    async fn get_tx_for_op_return(&self, _address: Address, _amount: u128, _data: H256) -> Result<Option<Txid>, Error> {
        // direct lookup not supported by bitcoin core
        Ok(None)
    }
}

/// Extension trait for transaction, adding methods to help to match the Transaction to Replace/Redeem requests
pub trait TransactionExt {
    fn get_op_return(&self) -> Option<H256>;
    fn get_op_return_bytes(&self) -> Option<[u8; 34]>;
    fn get_payment_amount_to(&self, dest: Payload) -> Option<u64>;
    fn extract_output_addresses(&self) -> Vec<Payload>;
    fn extract_indexed_output_addresses(&self) -> Vec<(usize, Payload)>;
    fn extract_return_to_self_address(&self, destination: &Payload) -> Result<Option<(usize, Payload)>, Error>;
}

impl TransactionExt for Transaction {
    /// Extract the hash from the OP_RETURN uxto, if present
    fn get_op_return(&self) -> Option<H256> {
        self.get_op_return_bytes().map(|x| H256::from_slice(&x[2..]))
    }

    /// Extract the bytes of the OP_RETURN uxto, if present
    fn get_op_return_bytes(&self) -> Option<[u8; 34]> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|x| {
            // check that the length is 34 bytes
            let arr: [u8; 34] = x.script_pubkey.to_bytes().as_slice().try_into().ok()?;
            // check that it starts with op_return (0x6a), then 32 as the length indicator
            match arr {
                [0x6a, 32, ..] => Some(arr),
                _ => None,
            }
        })
    }

    /// Get the amount of btc that self sent to `dest`, if any
    fn get_payment_amount_to(&self, dest: Payload) -> Option<u64> {
        self.output.iter().find_map(|uxto| {
            let payload = Payload::from_script(&uxto.script_pubkey).ok()?;
            if payload == dest {
                Some(uxto.value)
            } else {
                None
            }
        })
    }

    /// return the addresses that are used as outputs with non-zero value in this transaction
    fn extract_output_addresses(&self) -> Vec<Payload> {
        self.extract_indexed_output_addresses()
            .into_iter()
            .map(|(_idx, val)| val)
            .collect()
    }

    /// return the addresses that are used as outputs with non-zero value in this transaction,
    /// together with their index
    fn extract_indexed_output_addresses(&self) -> Vec<(usize, Payload)> {
        self.output
            .iter()
            .enumerate()
            .filter(|(_, x)| x.value > 0)
            .filter_map(|(idx, tx_out)| Some((idx, Payload::from_script(&tx_out.script_pubkey).ok()?)))
            .collect()
    }

    /// return index and address of the return-to-self (or None if it does not exist)
    fn extract_return_to_self_address(&self, destination: &Payload) -> Result<Option<(usize, Payload)>, Error> {
        let mut return_to_self_addresses = self
            .extract_indexed_output_addresses()
            .into_iter()
            .filter(|(_idx, x)| x != destination)
            .collect::<Vec<_>>();

        // register return-to-self address if it exists
        match return_to_self_addresses.len() {
            0 => Ok(None),                                     // no return-to-self
            1 => Ok(Some(return_to_self_addresses.remove(0))), // one return-to-self address
            _ => Err(Error::TooManyReturnToSelfAddresses),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::bitcoin::hashes::{hex::FromHex, sha256::Hash as Sha256Hash, Hash};

    #[test]
    fn test_op_return_hashing() {
        let raw = Vec::from_hex("6a208703723a787b0f989110b49fd5e1cf1c2571525d564bf384b5aa9e340c9ad8bd").unwrap();
        let script_hash = Sha256Hash::hash(&raw);

        let expected = "6ed3928fdcf7375b9622746eb46f8e97a2832a0c43000e3d86774fecb74ee67e";
        let expected = Sha256Hash::from_slice(&hex::decode(expected).unwrap()).unwrap();

        assert_eq!(expected, script_hash);
    }
}
