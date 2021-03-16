#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::{BtcAddress, BtcRelayPallet, PolkaBtcProvider};
use async_trait::async_trait;
use bitcoin::{
    secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey},
    serialize, BitcoinCoreApi, Block, BlockHash, BlockHeader, Error as BitcoinError,
    GetBlockResult, Hash, LockedTransaction, Network, OutPoint, PartialAddress, PartialMerkleTree,
    Script, Transaction, TransactionMetadata, TxIn, TxOut, Txid, Uint256, PUBLIC_KEY_SIZE,
};
use rand::{thread_rng, Rng};
use sp_core::{H160, H256, U256};
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::delay_for;

/// A simulated bitcoin-core interface. It combines the roles of bitcoin-core and the
/// staked relayer: it automatically relays the generated transactions to the parachain.
/// It does the minimum amount of work it can get away with, and the relayed data may
/// be technically invalid. For example, all generated transactions share the same dummy
/// input uxto.
#[derive(Clone)]
pub struct MockBitcoinCore {
    provider: PolkaBtcProvider,
    blocks: Arc<RwLock<Vec<Block>>>,
    mempool: Arc<RwLock<Vec<Transaction>>>,
    transaction_creation_lock: Arc<Mutex<()>>,
}

impl MockBitcoinCore {
    /// Creates a new instance, and initializes parachain's btc-relay
    pub async fn new(provider: PolkaBtcProvider) -> Self {
        let ret = Self {
            provider,
            blocks: Arc::new(RwLock::new(vec![])),
            mempool: Arc::new(RwLock::new(vec![])),
            transaction_creation_lock: Arc::new(Mutex::new(())),
        };

        let address = BtcAddress::P2PKH(H160::from([0; 20]));
        let block = ret
            .generate_block_with_transaction(&Self::generate_normal_transaction(&address, 10000))
            .await;
        let raw_block_header = serialize(&block.header);
        ret.provider
            .initialize_btc_relay(raw_block_header.try_into().unwrap(), 0)
            .await
            .unwrap();

        ret
    }

    /// Creates a new instance, but does not initializes parachain's btc-relay
    pub async fn new_uninitialized(provider: PolkaBtcProvider) -> Self {
        Self {
            provider,
            blocks: Arc::new(RwLock::new(vec![])),
            mempool: Arc::new(RwLock::new(vec![])),
            transaction_creation_lock: Arc::new(Mutex::new(())),
        }
    }

    /// relay a given block to the parachain
    async fn send_block(&self, block: Block) {
        let raw_block_header = serialize(&block.header);
        self.provider
            .store_block_header(raw_block_header.try_into().unwrap())
            .await
            .unwrap();
    }

    async fn generate_block_with_transaction(&self, transaction: &Transaction) -> Block {
        let target = U256::from(2).pow(254.into());
        let mut bytes = [0u8; 32];
        target.to_big_endian(&mut bytes);
        let target = Uint256::from_be_bytes(bytes);
        let mut blocks = self.blocks.write().await;

        let prev_blockhash = if blocks.is_empty() {
            Default::default()
        } else {
            blocks[blocks.len() - 1].header.block_hash()
        };

        let mut block = Block {
            txdata: vec![
                Self::generate_coinbase_transaction(
                    &BtcAddress::P2PKH(H160::from([1; 20])),
                    10000,
                    blocks.len() as u32,
                ),
                transaction.clone(),
            ],
            header: BlockHeader {
                version: 2,
                merkle_root: Default::default(),
                bits: BlockHeader::compact_target_from_u256(&target),
                nonce: 0,
                prev_blockhash,
                time: 1,
            },
        };
        block.header.merkle_root = block.merkle_root();

        loop {
            if let Ok(_) = block.header.validate_pow(&target) {
                break;
            }
            block.header.nonce += 1;
        }

        blocks.push(block.clone());

        block
    }

    fn generate_normal_transaction<A: PartialAddress + Send + 'static>(
        address: &A,
        reward: u64,
    ) -> Transaction {
        let address: BtcAddress =
            BtcAddress::decode_str(&address.encode_str(Network::Regtest).unwrap()).unwrap();
        let address = Script::from(address.to_script().as_bytes().to_vec());

        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    // random txid as input: it is not checked anyway. We ony need to make sure
                    // it is not equal to Outpoint::null, because that would be treated as a
                    // coinbase transaction
                    txid: Txid::from_slice(&[1; 32]).unwrap(),
                    vout: 0,
                },
                witness: vec![],
                // actual contents of don't script_sig don't really matter as long as it contains
                // a parsable script
                script_sig: Script::from(vec![
                    0, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234,
                    210, 186, 21, 187, 98, 38, 255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123,
                    216, 232, 168, 2, 32, 72, 126, 179, 207, 142, 8, 99, 8, 32, 78, 244, 166, 106,
                    160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12, 194, 240, 212, 3,
                    120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247,
                    165, 78, 111, 80, 79, 50, 200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253,
                    134, 127, 212, 51, 33, 2, 128, 200, 184, 235, 148, 25, 43, 34, 28, 173, 55, 54,
                    189, 164, 187, 243, 243, 152, 7, 84, 210, 85, 156, 238, 77, 97, 188, 240, 162,
                    197, 105, 62, 82, 174,
                ]),
                // not checked
                sequence: 0,
            }],
            output: vec![TxOut {
                script_pubkey: address,
                value: reward,
            }],
            lock_time: 0,
            version: 2,
        }
    }

    fn generate_coinbase_transaction(
        address: &BtcAddress,
        reward: u64,
        height: u32,
    ) -> Transaction {
        let address = Script::from(address.to_script().as_bytes().to_vec());

        // note that we set lock_time to height, otherwise we might generate blocks with
        // identical block hashes
        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::null(), // coinbase
                witness: vec![],
                script_sig: Default::default(),
                sequence: u32::max_value(),
            }],
            output: vec![TxOut {
                script_pubkey: address,
                value: reward,
            }],
            lock_time: height,
            version: 1,
        }
    }

    /// send a transaction to the mempool
    pub async fn send_to_mempool(&self, transaction: Transaction) {
        self.mempool.write().await.push(transaction);
    }

    /// add all transactions from the mempool onto the blockchain
    pub async fn flush_mempool(&self) {
        while let Some(transaction) = self.mempool.write().await.pop() {
            let block = self.generate_block_with_transaction(&transaction).await;
            self.send_block(block).await;
        }
    }
}

#[async_trait]
impl BitcoinCoreApi for MockBitcoinCore {
    async fn wait_for_block(
        &self,
        height: u32,
        _delay: Duration,
        _num_confirmations: u32,
    ) -> Result<BlockHash, BitcoinError> {
        loop {
            let blocks = self.blocks.read().await;
            if let Some(block) = blocks.get(height as usize + 1) {
                return Ok(block.header.block_hash());
            }
            drop(blocks); // release the lock
            delay_for(Duration::from_secs(1)).await;
        }
    }
    async fn get_block_count(&self) -> Result<u64, BitcoinError> {
        Ok((self.blocks.read().await.len() - 1).try_into().unwrap())
    }
    async fn get_raw_tx_for(
        &self,
        txid: &Txid,
        _block_hash: &BlockHash,
    ) -> Result<Vec<u8>, BitcoinError> {
        let blocks = self.blocks.read().await;

        let transaction = blocks
            .iter()
            .find_map(|x| x.txdata.iter().find(|y| &y.txid() == txid))
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;

        Ok(serialize(transaction))
    }
    async fn get_proof_for(
        &self,
        txid: Txid,
        _block_hash: &BlockHash,
    ) -> Result<Vec<u8>, BitcoinError> {
        let mut proof = Vec::new();
        let blocks = self.blocks.read().await;

        let block = blocks
            .iter()
            .find(|x| x.txdata.iter().any(|y| y.txid() == txid))
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;

        // part one of the proof: the serialized block header
        proof.append(&mut serialize(&block.header));

        // part two: info about the transactions (we assume the txid is at index 1)
        let txids = block.txdata.iter().map(|x| x.txid()).collect::<Vec<_>>();
        let partial_merkle_tree = PartialMerkleTree::from_txids(&txids, &[false, true]);
        proof.append(&mut serialize(&partial_merkle_tree));

        Ok(proof)
    }
    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks
            .get(height as usize)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.header.block_hash())
    }
    async fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError> {
        Ok(self
            .blocks
            .read()
            .await
            .iter()
            .any(|x| x.block_hash() == block_hash))
    }
    async fn get_new_address<A: PartialAddress + Send + 'static>(&self) -> Result<A, BitcoinError> {
        let bytes: [u8; 20] = (0..20)
            .map(|_| thread_rng().gen::<u8>())
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap();
        let address = BtcAddress::P2PKH(H160::from(bytes));
        Ok(A::decode_str(&address.encode_str(Network::Regtest)?)?)
    }
    async fn get_new_public_key<P: From<[u8; PUBLIC_KEY_SIZE]> + 'static>(
        &self,
    ) -> Result<P, BitcoinError> {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let secret_key = SecretKey::new(&mut rng);
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(P::from(public_key.serialize()))
    }
    async fn add_new_deposit_key<P: Into<[u8; PUBLIC_KEY_SIZE]> + Send + Sync + 'static>(
        &self,
        _public_key: P,
        _secret_key: Vec<u8>,
    ) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        Ok(blocks[blocks.len() - 1].block_hash())
    }
    async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks
            .iter()
            .find(|x| &x.block_hash() == hash)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.clone())
    }
    async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks
            .iter()
            .find(|x| &x.block_hash() == hash)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.header.clone())
    }
    async fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, BitcoinError> {
        let blocks = self.blocks.read().await;

        let (block_height, block) = blocks
            .iter()
            .enumerate()
            .find(|x| &x.1.block_hash() == hash)
            .ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(GetBlockResult {
            height: block_height,
            hash: block.block_hash(),
            confirmations: Default::default(),
            size: Default::default(),
            strippedsize: Default::default(),
            weight: Default::default(),
            version: Default::default(),
            version_hex: Default::default(),
            merkleroot: Default::default(),
            tx: Default::default(),
            time: Default::default(),
            mediantime: Default::default(),
            nonce: Default::default(),
            bits: Default::default(),
            difficulty: Default::default(),
            chainwork: Default::default(),
            n_tx: Default::default(),
            previousblockhash: Default::default(),
            nextblockhash: Default::default(),
        })
    }
    async fn get_mempool_transactions<'a>(
        self: &'a Self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>
    {
        let transactions = (*self.mempool.read().await).clone();
        Ok(Box::new(transactions.into_iter().map(|x| Ok(x))))
    }
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        _op_timeout: Duration,
        _num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let (block_height, block) = loop {
            // we have to be careful not to deadlock, so limit the scope of the lock
            let blocks = (*self.blocks.read().await).clone();

            if let Some(x) = blocks
                .iter()
                .enumerate()
                .find(|x| x.1.txdata[1].txid() == txid)
            {
                break (x.0, x.1.clone());
            }
            tokio::time::delay_for(Duration::from_secs(1)).await;
        };
        let block_hash = block.block_hash();
        let proof = self.get_proof_for(txid, &block_hash).await.unwrap();
        let raw_tx = self.get_raw_tx_for(&txid, &block_hash).await.unwrap();

        Ok(TransactionMetadata {
            block_hash,
            proof,
            raw_tx,
            txid,
            block_height: block_height as u32,
        })
    }
    async fn create_transaction<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<LockedTransaction, BitcoinError> {
        let mut transaction = MockBitcoinCore::generate_normal_transaction(&address, sat);

        if let Some(request_id) = request_id {
            // add an output with the op_return to the transaction
            let mut op_return_script = vec![0x6a, 32];
            op_return_script.append(&mut request_id.to_fixed_bytes().to_vec());
            let op_return = TxOut {
                value: 0,
                script_pubkey: Script::from(op_return_script),
            };
            transaction.output.push(op_return);
        }

        Ok(LockedTransaction::new(
            transaction,
            Some(self.transaction_creation_lock.clone().lock_owned().await),
        ))
    }
    async fn send_transaction(&self, transaction: LockedTransaction) -> Result<Txid, BitcoinError> {
        let block = self
            .generate_block_with_transaction(&transaction.transaction)
            .await;
        self.send_block(block.clone()).await;
        Ok(transaction.transaction.txid())
    }
    async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<Txid, BitcoinError> {
        let tx = self.create_transaction(address, sat, request_id).await?;
        let txid = self.send_transaction(tx).await?;
        Ok(txid)
    }
    async fn send_to_address<A: PartialAddress + Send + 'static>(
        &self,
        address: A,
        sat: u64,
        request_id: Option<H256>,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let txid = self
            .create_and_send_transaction(address, sat, request_id)
            .await
            .unwrap();
        let metadata = self
            .wait_for_transaction_metadata(txid, op_timeout, num_confirmations)
            .await
            .unwrap();
        Ok(metadata)
    }
    async fn create_wallet(&self, _wallet: &str) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn wallet_has_public_key<P>(&self, _public_key: P) -> Result<bool, BitcoinError>
    where
        P: Into<[u8; PUBLIC_KEY_SIZE]>
            + From<[u8; PUBLIC_KEY_SIZE]>
            + Clone
            + PartialEq
            + Send
            + Sync
            + 'static,
    {
        Ok(true)
    }
}
