pub mod cli;

mod addr;
mod error;
mod iter;

pub use addr::PartialAddress;
use async_trait::async_trait;
use backoff::{backoff::Backoff, future::retry, ExponentialBackoff};
pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::{opcodes::all as opcodes, script::Builder},
        consensus::encode::{deserialize, serialize},
        hash_types::BlockHash,
        hashes::{hex::ToHex, Hash},
        secp256k1,
        secp256k1::{constants::PUBLIC_KEY_SIZE, SecretKey},
        util::{address::Payload, key, merkleblock::PartialMerkleTree, psbt::serialize::Serialize, uint::Uint256},
        Address, Amount, Block, BlockHeader, Network, OutPoint, PrivateKey, PubkeyHash, PublicKey, Script, ScriptHash,
        Transaction, TxIn, TxMerkleNode, TxOut, Txid, WPubkeyHash, WScriptHash,
    },
    bitcoincore_rpc_json::{CreateRawTransactionInput, GetBlockchainInfoResult, GetTransactionResult, WalletTxInfo},
    json::{self, AddressType, GetBlockResult},
    jsonrpc::{error::RpcError, Error as JsonRpcError},
    Auth, Client, Error as BitcoinError, RpcApi,
};
pub use error::{BitcoinRpcError, ConversionError, Error};
use esplora_btc_api::apis::configuration::Configuration as ElectrsConfiguration;
pub use iter::{reverse_stream_transactions, stream_blocks, stream_in_chain_transactions};
use log::{info, trace};
use serde_json::error::Category as SerdeJsonCategory;
use sp_core::H256;
use std::{convert::TryInto, future::Future, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, OwnedMutexGuard},
    time::{sleep, timeout},
};

#[macro_use]
extern crate num_derive;

/// Average time to mine a Bitcoin block.
pub const BLOCK_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

const NOT_IN_MEMPOOL_ERROR_CODE: i32 = BitcoinRpcError::RpcInvalidAddressOrKey as i32;

// Time to sleep before retry on startup.
const RETRY_DURATION: Duration = Duration::from_millis(1000);

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

const ELECTRS_TESTNET_URL: &str = "https://btc-testnet.interlay.io";
const ELECTRS_MAINNET_URL: &str = "https://btc-mainnet.interlay.io";
const ELECTRS_LOCALHOST_URL: &str = "http://localhost:3002";

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

#[derive(Debug, Clone)]
pub struct TransactionMetadata {
    pub txid: Txid,
    pub proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub block_height: u32,
    pub block_hash: BlockHash,
}

#[async_trait]
pub trait BitcoinCoreApi {
    fn network(&self) -> Network;

    async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, Error>;

    async fn get_block_count(&self) -> Result<u64, Error>;

    async fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error>;

    async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error>;

    async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;

    async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, Error>;

    async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(&self) -> Result<P, Error>;

    async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
        &self,
        public_key: P,
        secret_key: Vec<u8>,
    ) -> Result<(), Error>;

    async fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

    async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error>;

    async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error>;

    async fn get_mempool_transactions<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + Send + 'a>, Error>;

    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    async fn create_transaction<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<LockedTransaction, Error>;

    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, Error>;

    async fn create_and_send_transaction<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<Txid, Error>;

    async fn send_to_address<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    async fn create_or_load_wallet(&self) -> Result<(), Error>;

    async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, Error>
    where
        P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static;

    async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), Error>;

    async fn rescan_blockchain(&self, start_height: usize) -> Result<(), Error>;

    async fn find_duplicate_payments(&self, transaction: &Transaction) -> Result<Vec<(Txid, BlockHash)>, Error>;
}

pub struct LockedTransaction {
    pub transaction: Transaction,
    pub recipient: String,
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

fn parse_bitcoin_network(src: &str) -> Result<Network, Error> {
    match src {
        "main" => Ok(Network::Bitcoin),
        "test" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        _ => Err(Error::InvalidBitcoinNetwork),
    }
}

/// Connect to a bitcoin-core full node or timeout.
async fn connect(rpc: &Client, connection_timeout: Duration) -> Result<Network, Error> {
    info!("Connecting to bitcoin-core...");
    timeout(connection_timeout, async move {
        loop {
            match rpc.get_blockchain_info().map_err(Into::<Error>::into) {
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
                Ok(GetBlockchainInfoResult { chain, .. }) => {
                    info!("Connected to {}", chain);
                    return parse_bitcoin_network(&chain);
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
        Ok(Client::new(&url, self.auth.clone())?)
    }

    pub fn build_with_network(self, network: Network) -> Result<BitcoinCore, Error> {
        Ok(BitcoinCore::new(
            self.new_client()?,
            self.wallet_name,
            network,
            self.electrs_url,
        ))
    }

    pub async fn build_and_connect(self, connection_timeout: Duration) -> Result<BitcoinCore, Error> {
        let client = self.new_client()?;
        let network = connect(&client, connection_timeout).await?;
        Ok(BitcoinCore::new(client, self.wallet_name, network, self.electrs_url))
    }
}

#[derive(Clone)]
pub struct BitcoinCore {
    rpc: Arc<Client>,
    wallet_name: Option<String>,
    network: Network,
    transaction_creation_lock: Arc<Mutex<()>>,
    electrs_config: ElectrsConfiguration,
}

impl BitcoinCore {
    fn new(client: Client, wallet_name: Option<String>, network: Network, electrs_url: Option<String>) -> Self {
        BitcoinCore {
            rpc: Arc::new(client),
            wallet_name,
            network,
            transaction_creation_lock: Arc::new(Mutex::new(())),
            electrs_config: ElectrsConfiguration {
                base_path: electrs_url.unwrap_or_else(|| {
                    match network {
                        Network::Bitcoin => ELECTRS_MAINNET_URL,
                        Network::Testnet => ELECTRS_TESTNET_URL,
                        _ => ELECTRS_LOCALHOST_URL,
                    }
                    .to_owned()
                }),
                ..Default::default()
            },
        }
    }

    /// Wait indefinitely for the node to sync.
    pub async fn sync(&self) -> Result<(), Error> {
        info!("Waiting for bitcoin-core to sync...");
        loop {
            let info = self.rpc.get_blockchain_info()?;
            // NOTE: initial_block_download is always true on regtest
            if !info.initial_block_download || info.verification_progress.eq(&1.0) {
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
        outputs.insert(address, serde_json::Value::from(amount.as_btc()));

        if let Some(request_id) = request_id {
            // add the op_return data - bitcoind will add op_return and the length automatically
            outputs.insert("data".to_string(), serde_json::Value::from(request_id.to_hex()));
        }

        let args = [
            serde_json::to_value::<&[json::CreateRawTransactionInput]>(&[])?,
            serde_json::to_value(outputs)?,
        ];
        Ok(self.rpc.call("createrawtransaction", &args)?)
    }

    #[cfg(feature = "regtest-manual-mining")]
    pub fn mine_block(&self) -> Result<(), Error> {
        self.rpc
            .generate_to_address(1, &self.rpc.get_new_address(None, Some(AddressType::Bech32))?)?;
        Ok(())
    }

    pub fn encode_address<A: PartialAddress + Send + 'static>(&self, address: A) -> Result<String, Error> {
        Ok(address.encode_str(self.network)?)
    }

    async fn with_wallet<F, R, T>(&self, call: F) -> Result<T, Error>
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
                Err(inner) if inner.is_wallet_error() => {
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
    async fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error> {
        Ok(self
            .rpc
            .get_balance(min_confirmations.map(|x| x.try_into().unwrap_or_default()), None)?)
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

    /// Checks if the local full node has seen the specified block hash.
    ///
    /// # Arguments
    /// * `block_hash` - hash of the block to verify
    async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error> {
        match self.rpc.get_block(&block_hash) {
            Ok(_) => Ok(true),
            Err(BitcoinError::JsonRpc(JsonRpcError::Rpc(err)))
                if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcInvalidAddressOrKey =>
            {
                Ok(false) // block not found
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Gets a new address from the wallet
    async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, Error> {
        let address = self.rpc.get_new_address(None, Some(AddressType::Bech32))?;
        Ok(A::decode_str(&address.to_string())?)
    }

    /// Gets a new public key for an address in the wallet
    async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(&self) -> Result<P, Error> {
        let address = self.rpc.get_new_address(None, Some(AddressType::Bech32))?;
        let address_info = self.rpc.get_address_info(&address)?;
        let public_key = address_info.pubkey.ok_or(Error::MissingPublicKey)?;
        Ok(P::from(public_key.key.serialize()))
    }

    /// Derive and import the private key for the master public key and public secret
    async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
        &self,
        public_key: P,
        secret_key: Vec<u8>,
    ) -> Result<(), Error> {
        let address = Address::p2wpkh(&PublicKey::from_slice(&public_key.into())?, self.network)
            .map_err(ConversionError::from)?;
        let private_key = self.rpc.dump_private_key(&address)?;
        let deposit_secret_key =
            addr::calculate_deposit_secret_key(private_key.key, SecretKey::from_slice(&secret_key)?)?;
        self.rpc.import_private_key(
            &PrivateKey {
                compressed: private_key.compressed,
                network: self.network,
                key: deposit_secret_key,
            },
            None,
            // rescan true by default
            Some(false),
        )?;
        Ok(())
    }

    async fn get_best_block_hash(&self) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_best_block_hash()?)
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        Ok(self.rpc.get_block(hash)?)
    }

    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, Error> {
        Ok(self.rpc.get_block_header(hash)?)
    }

    async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error> {
        Ok(self.rpc.get_block_info(hash)?)
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
            match self.rpc.get_raw_transaction_info(&txid, None) {
                Ok(x) => Some(x.transaction().map_err(Into::into)),
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
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let (block_height, block_hash) = retry(get_exponential_backoff(), || async {
            Ok(match self.rpc.get_transaction(&txid, None) {
                Ok(GetTransactionResult {
                    info:
                        WalletTxInfo {
                            confirmations,
                            blockhash: Some(hash),
                            blockheight: Some(height),
                            ..
                        },
                    ..
                }) if confirmations >= 0 && confirmations as u32 >= num_confirmations => Ok((height, hash)),
                Ok(_) => Err(Error::ConfirmationError),
                Err(e) => Err(e.into()),
            }?)
        })
        .await?;

        let proof = retry(get_exponential_backoff(), || async {
            Ok(self.get_proof(txid, &block_hash).await?)
        })
        .await?;

        let raw_tx = retry(get_exponential_backoff(), || async {
            Ok(self.get_raw_tx(&txid, &block_hash).await?)
        })
        .await?;

        Ok(TransactionMetadata {
            txid,
            proof,
            raw_tx,
            block_height,
            block_hash,
        })
    }

    /// Creates and return a transaction; it is not submitted to the mempool. While the returned value
    /// is alive, no other transactions can be created (this is guarded by a mutex). This prevents
    /// accidental double spending.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `request_id` - the issue/redeem/replace id for which this transfer is being made
    async fn create_transaction<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<LockedTransaction, Error> {
        self.with_wallet(|| async {
            let address_string = address.encode_str(self.network)?;

            // create raw transaction that includes the op_return (if any). If we were to add the op_return
            // after funding, the fees might be insufficient. An alternative to our own version of
            // this function would be to call create_raw_transaction (without the _hex suffix), and
            // to add the op_return afterwards. However, this function fails if no inputs are
            // specified, as is the case for us prior to calling fund_raw_transaction.
            let raw_tx = self.create_raw_transaction_hex(address_string.clone(), Amount::from_sat(sat), request_id)?;

            // ensure no other fund_raw_transaction calls are made until we submitted the
            // transaction to the bitcoind. If we don't do this, the same uxto may be used
            // as input twice (i.e. double spend)
            let lock = self.transaction_creation_lock.clone().lock_owned().await;

            // fund the transaction: adds required inputs, and possibly a return-to-self output
            let funded_raw_tx = self.rpc.fund_raw_transaction(raw_tx, None, None)?;

            // sign the transaction
            let signed_funded_raw_tx =
                self.rpc
                    .sign_raw_transaction_with_wallet(&funded_raw_tx.transaction()?, None, None)?;

            // Make sure signing is successful
            if signed_funded_raw_tx.errors.is_some() {
                return Err(Error::TransactionSigningError);
            }

            let transaction = signed_funded_raw_tx.transaction()?;

            Ok(LockedTransaction::new(transaction, address_string, Some(lock)))
        })
        .await
    }

    /// Submits a transaction to the mempool
    ///
    /// # Arguments
    /// * `transaction` - The transaction created by create_transaction
    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, Error> {
        // place the transaction into the mempool, this is fine to retry
        let txid = self
            .with_wallet(|| async { Ok(self.rpc.send_raw_transaction(&transaction.transaction)?) })
            .await?;
        Ok(txid)
    }

    /// Send an amount of Bitcoin to an address, but only submit the transaction
    /// to the mempool; this method does not wait until the block is included in
    /// the blockchain.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `request_id` - the issue/redeem/replace id for which this transfer is being made
    async fn create_and_send_transaction<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<Txid, Error> {
        let tx = self.create_transaction(address, sat, request_id).await?;
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
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn send_to_address<A: PartialAddress + Send + Sync + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let txid = self.create_and_send_transaction(address, sat, request_id).await?;

        #[cfg(feature = "regtest-mine-on-tx")]
        self.rpc
            .generate_to_address(1, &self.rpc.get_new_address(None, Some(AddressType::Bech32))?)?;

        Ok(self.wait_for_transaction_metadata(txid, num_confirmations).await?)
    }

    /// Create or load a wallet on Bitcoin Core.
    async fn create_or_load_wallet(&self) -> Result<(), Error> {
        let wallet_name = if let Some(ref wallet_name) = self.wallet_name {
            wallet_name
        } else {
            return Err(Error::WalletNotFound);
        };

        // NOTE: bitcoincore-rpc does not expose listwalletdir
        if self.rpc.list_wallets()?.contains(wallet_name) || self.rpc.load_wallet(wallet_name).is_ok() {
            // wallet already loaded
            return Ok(());
        }
        // wallet does not exist, create
        self.rpc.create_wallet(wallet_name, None, None, None, None)?;
        Ok(())
    }

    async fn wallet_has_public_key<P>(&self, public_key: P) -> Result<bool, Error>
    where
        P: Into<[u8; PUBLIC_KEY_SIZE]> + From<[u8; PUBLIC_KEY_SIZE]> + Clone + PartialEq + Send + Sync + 'static,
    {
        self.with_wallet(|| async {
            let address = Address::p2wpkh(&PublicKey::from_slice(&public_key.clone().into())?, self.network)
                .map_err(ConversionError::from)?;
            let address_info = self.rpc.get_address_info(&address)?;
            let wallet_pubkey = address_info.pubkey.ok_or(Error::MissingPublicKey)?;
            Ok(P::from(wallet_pubkey.key.serialize()) == public_key)
        })
        .await
    }

    async fn import_private_key(&self, privkey: PrivateKey) -> Result<(), Error> {
        self.with_wallet(|| async { Ok(self.rpc.import_private_key(&privkey, None, None)?) })
            .await
    }

    async fn rescan_blockchain(&self, start_height: usize) -> Result<(), Error> {
        self.rpc.rescan_blockchain(Some(start_height), None)?;
        Ok(())
    }

    async fn find_duplicate_payments(&self, transaction: &Transaction) -> Result<Vec<(Txid, BlockHash)>, Error> {
        let op_return_bytes = transaction.get_op_return_bytes().unwrap();
        let script_hash = bitcoincore_rpc::bitcoin::hashes::sha256::Hash::hash(&op_return_bytes);
        let txs = esplora_btc_api::apis::scripthash_api::get_txs_by_scripthash(
            &self.electrs_config,
            &hex::encode(script_hash),
        )
        .await?;

        let extract_block_hash = |tx: &esplora_btc_api::models::Transaction| {
            if let Some(status) = &tx.status {
                if let Some(block_hash) = &status.block_hash {
                    return Ok(BlockHash::from_str(block_hash)?);
                }
            }
            Err(ConversionError::BlockHashError)
        };
        let extract_data = |tx: &esplora_btc_api::models::Transaction| {
            let txid = Txid::from_str(&tx.txid)?;
            let block_hash = extract_block_hash(tx)?;
            Ok((txid, block_hash))
        };

        let ret: Result<Vec<_>, ConversionError> = txs
            .iter()
            .filter_map(|x| match extract_data(x) {
                Ok((txid, _)) if txid == transaction.txid() => None,
                ret => Some(ret),
            })
            .collect();
        Ok(ret?)
    }
}

/// Extension trait for transaction, adding methods to help to match the Transaction to Replace/Redeem requests
pub trait TransactionExt {
    fn get_op_return(&self) -> Option<H256>;
    fn get_op_return_bytes(&self) -> Option<[u8; 34]>;
    fn get_payment_amount_to<A: PartialAddress + PartialEq>(&self, dest: A) -> Option<u64>;
    fn extract_input_addresses<A: PartialAddress>(&self) -> Vec<A>;
    fn extract_output_addresses<A: PartialAddress>(&self) -> Vec<A>;
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
    fn get_payment_amount_to<A: PartialAddress + PartialEq>(&self, dest: A) -> Option<u64> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|uxto| {
            let payload = Payload::from_script(&uxto.script_pubkey)?;
            let address = A::from_payload(payload).ok()?;
            if address == dest {
                Some(uxto.value)
            } else {
                None
            }
        })
    }

    /// return the addresses that are used as inputs in this transaction
    fn extract_input_addresses<A: PartialAddress>(&self) -> Vec<A> {
        self.input
            .iter()
            .filter_map(|vin| vin_to_address(vin.clone()).ok())
            .collect::<Vec<A>>()
    }

    /// return the addresses that are used as outputs with non-zero value in this transaction
    fn extract_output_addresses<A: PartialAddress>(&self) -> Vec<A> {
        self.output
            .iter()
            .filter(|x| x.value > 0)
            .filter_map(|tx_out| {
                let payload = Payload::from_script(&tx_out.script_pubkey)?;
                PartialAddress::from_payload(payload).ok()
            })
            .collect()
    }
}

// https://github.com/interlay/interbtc/blob/cc5c16b28ef705e0774654dd94b813d9d35e12ec/crates/bitcoin/src/parser.rs#L277
fn parse_compact_uint(varint: &[u8]) -> Result<(u64, usize), Error> {
    match varint.get(0).ok_or(Error::ParsingError)? {
        0xfd => {
            let mut num_bytes: [u8; 2] = Default::default();
            num_bytes.copy_from_slice(varint.get(1..3).ok_or(Error::ParsingError)?);
            Ok((u16::from_le_bytes(num_bytes) as u64, 3))
        }
        0xfe => {
            let mut num_bytes: [u8; 4] = Default::default();
            num_bytes.copy_from_slice(varint.get(1..5).ok_or(Error::ParsingError)?);
            Ok((u32::from_le_bytes(num_bytes) as u64, 5))
        }
        0xff => {
            let mut num_bytes: [u8; 8] = Default::default();
            num_bytes.copy_from_slice(varint.get(1..9).ok_or(Error::ParsingError)?);
            Ok((u64::from_le_bytes(num_bytes) as u64, 9))
        }
        _ => Ok((varint[0] as u64, 1)),
    }
}

fn vin_to_address<A: PartialAddress>(vin: TxIn) -> Result<A, Error> {
    let script = if vin.witness.len() >= 2 {
        Script::new_v0_wpkh(&WPubkeyHash::hash(&vin.witness[1]))
    } else {
        let input_script = vin.script_sig.as_bytes();
        if input_script.is_empty() {
            // ignore empty scripts (i.e. witness)
            return Err(Error::ParsingError);
        }

        let mut p2pkh = true;
        let mut pos = if input_script[0] == 0x00 {
            p2pkh = false;
            1
        } else {
            0
        };

        // TODO: reuse logic from bitcoin crate
        let last = std::cmp::min(pos + 3, input_script.len());
        let (size, len) = parse_compact_uint(input_script.get(pos..last).ok_or(Error::ParsingError)?)?;
        pos += len;
        // skip sigs
        pos += size as usize;
        // parse redeem_script or compressed public_key
        let last = std::cmp::min(pos + 3, input_script.len());
        let (_size, len) = parse_compact_uint(input_script.get(pos..last).ok_or(Error::ParsingError)?)?;
        pos += len;

        let bytes = input_script.get(pos..).ok_or(Error::ParsingError)?;

        if p2pkh {
            Script::new_p2pkh(&PubkeyHash::hash(bytes))
        } else {
            Script::new_p2sh(&ScriptHash::hash(bytes))
        }
    };

    Ok(PartialAddress::from_payload(
        Payload::from_script(&script).ok_or(ConversionError::InvalidPayload)?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoincore_rpc::bitcoin::{hashes::hex::FromHex, OutPoint, Script, Transaction};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_duplicate_payments_succeeds() {
        let bitcoin_core = BitcoinCoreBuilder::new("localhost".to_string())
            .build_with_network(Network::Testnet)
            .unwrap();

        let raw_tx = Vec::from_hex("020000000001011f876af6685f6e872b18d288a614adfd21d0246f52e3ca086cdb15d125837a270100000000fdffffff020000000000000000226a208b26f7cf49e1ad4d9f81d237933da8810644a85ac25b3c22a6a2324e1ba02efcba0e0000000000001600148cb0d2c0597a4b496370f94c2e1424d6d1e3432d02473044022023159d039a42095066036b25f08bf77dbf8a8813bf3d842aa998f7437e0da5d002202a102568194e3bba597a31f432c8d3beb5fca9129366f115831b4abba356aa4001210223a4dbc56f6d53a2014dfb106e754323da8e9c095cf9d68f627169f7c059d07a08e71f00").unwrap();
        let transaction: Transaction = deserialize(&raw_tx).unwrap();
        let result = bitcoin_core.find_duplicate_payments(&transaction).await.unwrap();
        // check that the transaction arg is excluded from the results
        assert!(!result.iter().any(|(txid, _)| txid == &transaction.txid()));
        // check that it does find the other transaction with the same op_return
        assert!(result.iter().any(|(txid, _)| txid
            == &Txid::from_hex("8bb6dacf9fca12550c2be9350994737e45cdcbd05d3ce6132141b0872661baec").unwrap()));
    }

    async fn test_electrs(url: &str, script_hex: &str, expected_txid: &str) {
        let config = ElectrsConfiguration {
            base_path: url.to_owned(),
            ..Default::default()
        };

        let script_bytes = Vec::from_hex(script_hex).unwrap();
        let script_hash = bitcoincore_rpc::bitcoin::hashes::sha256::Hash::hash(&script_bytes);

        let txs = esplora_btc_api::apis::scripthash_api::get_txs_by_scripthash(&config, &hex::encode(script_hash))
            .await
            .unwrap();
        assert!(txs.iter().any(|tx| { &tx.txid == expected_txid }));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore] // disabled until mainnet electrs is up and running
    async fn test_find_esplora_mainnet() {
        let script_hex = "6a24aa21a9ed932d00baa7d428106db4f785d398d60d0b9c1369c38448717db4a8f36d2512e3";
        let expected_txid = "d734d56c70ee7ac67d31a22f4b9a781619c5cff1803942b52036cd7eab1692e7";
        test_electrs(ELECTRS_MAINNET_URL, script_hex, expected_txid).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_esplora_testnet() {
        let script_hex = "6a208b26f7cf49e1ad4d9f81d237933da8810644a85ac25b3c22a6a2324e1ba02efc";
        let expected_txid = "ec736ccba2cb7d1a97145a7e98d32f8eec362cd140e917ce40842a492f43b49b";
        test_electrs(ELECTRS_TESTNET_URL, script_hex, expected_txid).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_find_esplora_testnet2() {
        let script_hex = "6a4c5054325b0f43c54432b8df76322d225c9759359f73b283e108441862c2ee6fe4a021f6825bee72311ec0f53dd7197d0e325dca9a45aa3af296294b42c667b6db214a5174001fe7f40004001f7a07000b02";
        let expected_txid = "ddfaa4f63b9cbdf72299b91074fbff13b02816f2a29109b2fecfd912a7476807";
        test_electrs(ELECTRS_TESTNET_URL, script_hex, expected_txid).await;
    }

    #[test]
    fn test_op_return_hashing() {
        let raw = Vec::from_hex("6a208703723a787b0f989110b49fd5e1cf1c2571525d564bf384b5aa9e340c9ad8bd").unwrap();
        let script_hash = bitcoincore_rpc::bitcoin::hashes::sha256::Hash::hash(&raw);

        let expected = "6ed3928fdcf7375b9622746eb46f8e97a2832a0c43000e3d86774fecb74ee67e";
        let expected = bitcoincore_rpc::bitcoin::hashes::sha256::Hash::from_hex(expected).unwrap();

        assert_eq!(expected, script_hash);
    }

    #[test]
    fn test_vin_to_address() {
        assert_eq!(
            // 1fd696a71ce2d9533d1e22cd113c8c8b33da4845716f42eb99968f3d88a4042c
            Address {
                payload: vin_to_address::<Payload>(TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: Script::default(),
                    sequence: 0,
                    witness: vec![
                        hex::decode("304402207abd7b0bf0b7c2c695293b5bac23ae2b5c0806a1a124dd39e693de3bec67a723022014bd3a35f2ba31768e1ed3e7bbc645e1c6c69218fa72edb2325c7580af62e46901").unwrap(),
                        hex::decode("037dbedcebf19e92d3d2f10846f3470797d7ba74f3faf111ab2fa94f77fd7e58d7").unwrap(),
                    ],
                }).unwrap(), network: Network::Testnet
            }.to_string(),
            "tb1q7e9x3k5gkx8dsgqwm455z3sa7maj4mc05mqnvf".to_string(),
            "p2wpkh"
        );

        assert_eq!(
            // 5ce470709bd532e092ddc01cf906c80e34d19ff7541ef03dabaedacfd7233f8d
            Address {
                payload: vin_to_address::<Payload>(TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: deserialize::<Script>(&hex::decode("1600144d99b19e36a28fc6a6bab9f48ba98652351bb3cb").unwrap()).unwrap(),
                    sequence: 0,
                    witness: vec![
                        hex::decode("30440220202345f4ef3f715a14e8e15e7ed54813c0d56d546c02fe1a419c1ce86d82c9ee0220180445abea2125cbde0db6ee5436cb9a98f5dad12865a6855e8a1c7f45c2984a01").unwrap(),
                        hex::decode("02b309205f020e2c9643f12ce0eea9ec5b3e1e3be99df61f629fe22687d7d80238").unwrap(),
                    ],
                }).unwrap(), network: Network::Testnet
            }.to_string(),
            "tb1qfkvmr83k528udf46h86gh2vx2g63hv7tkdufks".to_string(),
            "p2wpkh"
        );

        {
            // e9affb84743b91034582a56ac8a6f9c6815057edb7a1f4c0df6e78a4af4a9c7a
            let tx = deserialize::<Transaction>(&hex::decode("0100000001a2a20766d15406c23841d4e7a7348403624c723fcdbae1ce44654975f5400584010000006a47304402201f1ba72b4071b38905135ed08acbafb0926c42b9f709ff6d3e7d4f557b58e92f02203b2bcb227085c1a37d22fdc0a9c1ba73f69560aadaacf1144cb7d614bba7cd430121020c57dafca427593d3b9e323098c2ca0bb0512a23efa08d388147e1877cabc037ffffffff02f82a0000000000001976a9142c8e6dcfb9a2eb49118886f0ac1e6e6574d1636188ac30689359000000001976a914935bd02d1337ec8ff9b914f4a0159f1240d530f688ac00000000").unwrap()).unwrap();
            assert_eq!(
                Address {
                    payload: vin_to_address::<Payload>(tx.input[0].clone()).unwrap(),
                    network: Network::Testnet
                }
                .to_string(),
                "mgJnpiNHvZpTLZ8yX1Tnw8ieErvJt9gkA9".to_string(),
                "p2pkh"
            );
        }

        {
            // d3daa640b29ecbd306fcaede8d1e9b7c89e48f160c377247c5259ba73d1efcb8
            let tx = deserialize::<Transaction>(&hex::decode("01000000014f287eabcbb1656713a584763da163a7b58f58047f8e5576283cee592c1bb2e101000000910047304402205b8029966035bb3fe68135ead2ba15bb6226ff701e1be41d848c9b3e7bd8e8a80220487eb3cf8e086308204ef4a66aa0cfe33dd2aceaea5d3b9f4f0cc2f0d4037832014751210371d183b1091df2e50fd9f7a54e6f504f32c875501ee9d2a785af3efd867fd433210280c8b8eb94192b221cad3736bda4bbf3f3980754d2559cee4d61bcf0a2c5693e52aeffffffff0140aeeb02000000001976a914394c0ce031df961094c1531f81bfeed5e341a2c388ac00000000").unwrap()).unwrap();
            assert_eq!(
                Address {
                    payload: vin_to_address::<Payload>(tx.input[0].clone()).unwrap(),
                    network: Network::Testnet
                }
                .to_string(),
                "2NCwKFvap8M8q2c4qLRPdhyaEneQXTxynzM".to_string(),
                "p2sh"
            );
        }
    }

    #[test]
    fn test_extract_input_addresses() {
        // 5de91933c40bbb2ed7532e352e52e99a51987fd85d92fecee5fb1c0abccdc40a
        let tx = deserialize::<Transaction>(&hex::decode("0100000000010a6f3696e148abd79a11de9c856de2ab8c5d577dfb11504098dd7b20aebb5df1fb0100000000ffffffff2d0a3a53efdb9137335196b8e8411a7875a25e7f8f0d1caf2f8b34228f1d5378000000006b483045022100f5a08d7fec0f14dfb2951eb4ed1258819fe7581b1d1f3f80dac124bdb89c793f0220307b9864355f86f2fa89978514bcdc239452f77d6ff40ab1124e73a4487c01a80121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffba1431cf2a5dc4b07d86d788bd2e8444cbd3dd0cb35820be30eb7b90d3e48f0c000000006a4730440220377ea3fdead5fab0f771bfe1e7ac2084583dda7b7bdb39cce8a62a1092bed1ba0220608092e7233938de44329bb2eeabaae2911f06b224bbbc38228397bfc73011500121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffba0a2f37ffbe96731a0871b31da5dc9220d8b74895f56ec070e8587d9dd9ea06000000006a47304402206e3223bc0724e48416ebd05e94c1ccd249d00da81132a57b97ba6ae68c1e726802201de050b8e7138e774575b0d024a324d900476955144ad87b8a1bf876136bc1f60121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffba073447d593711edffe4dc94266b1c5b1985099854e99dd930185a66a4acd60000000006a47304402202974974b80aa509fbc5c8e6ac05667f41889dd89a49363715d0d3e9e0b68be1d022074d2dd3fe6db508081a829bf200f3d70f2366e797f2bf30ae4401d397da8f9370121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffb9fb6cf24186598c6bbcac7fef988a8e78ba40c619a3258673b460202364346a000000006a47304402206329eca504a17a00ec1425b95bc5659bda7f5d284920df966dd27c72ff2d6a4f0220068a83a3380def3ea19cc6506d1c5ea75e7299716d00aadcdc87065444b763cd0121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffb9f27cd3878f205d8dcc252b5a862cdfbede877dc88d0fec2c0d659b3bb3d767000000006b483045022100d9a019c934e7e8da7add5798e7795b0e910df87d755c8de83fd169415c085c410220723dd326f45c3ab40a9a6870400507cb76914cf40625df0c9aad60b2871ad5ba0121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffb9e4c0dd11326ea85d8804e4ed4a956fa2c80412b10f05a9243f788d9fb2c38a000000006b483045022100cac5e6c793cb0b8a2456d7e69170e796822d268aa82b01ea2796dec7d6c7138e0220326110c2b44dcb787689b8fbb435c1374fc5f14ec31754b065518dc0fe3e2c450121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffb9e158a00f1ed11728561655ccb43c3aa149343dd67d1f0e08a1788cdbec238d000000006b483045022100e53756fb299901d2093b1a94cbc23c133173ddf56ec7e24f80608c6f693f3e6302201f6e8f47a6943f4bb5c86ddc50ec89a5e914426d8c9e52796612a3e5e86da8540121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffffb9e0b662cb8d716ff42cc206e5142a17800fd1896022fad533f7931bf8bda19a000000006b483045022100db6b34d039b5a4de0621ceedf81c9871fe2a424211cf9e64bde58220fe4eef070220032d7bfdaee069627b4c2c6b7eff0510d56fdfb51a09ff1f887f21fa048b67820121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4eceffffffff02e2cb21000000000016001474542d769d4dcb7b988bd029f215ffb43370572db35de9210b00000016001487ca9164c3c704701e5f669b472287d4ec55f71a02483045022100c1b1c3576c05c6a9e7130f1353bde96044a3eeb420979e0539d38880058d9fe402201760bab2d7f5ca4ec206682244e8ba421a5358abdd8579d06a1bfda684bb87e00121033cbadaa31a30b53d7f22d3560527c1ecbac52d902738dac6520820730ffe4ece00000000000000000000000000").unwrap()).unwrap();
        assert_eq!(
            tx.extract_input_addresses::<Payload>()
                .iter()
                .map(|payload| Address {
                    payload: payload.clone(),
                    network: Network::Testnet
                }
                .to_string())
                .collect::<Vec<String>>(),
            vec![
                "tb1qsl9fzexrcuz8q8jlv6d5wg586nk9tac6ghv2qu",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC",
                "mstxBcqFZHroNeVAEBc9NiV383KTUXFyCC"
            ]
        );
    }
}
