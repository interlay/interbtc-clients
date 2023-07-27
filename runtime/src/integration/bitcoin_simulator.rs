#![cfg(all(feature = "testing-utils", feature = "parachain-metadata-kintsugi"))]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::{BtcAddress, BtcRelayPallet, InterBtcParachain, PartialAddress, RawBlockHeader, H160, H256, U256};
use async_trait::async_trait;
use bitcoin::{
    bitcoin_primitives::{absolute::Height, block::Version, ScriptBuf, Target},
    json::{
        self,
        bitcoin::{locktime::absolute::LockTime, Sequence, Witness},
    },
    secp256k1::{self, constants::SECRET_KEY_SIZE, Secp256k1, SecretKey},
    serialize, Address, Amount, BitcoinCoreApi, Block, BlockHash, BlockHeader, Error as BitcoinError, GetBlockResult,
    Hash, Network, OutPoint, PartialMerkleTree, PrivateKey, PublicKey, RawTransactionProof, SatPerVbyte, Script,
    Transaction, TransactionExt, TransactionMetadata, TxIn, TxMerkleNode, TxOut, Txid, PUBLIC_KEY_SIZE,
};
use rand::{thread_rng, Rng};
use std::{convert::TryInto, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, OwnedMutexGuard, RwLock},
    time::sleep,
};
/// A simulated bitcoin-core interface. It combines the roles of bitcoin-core and the
/// staked relayer: it automatically relays the generated transactions to the parachain.
/// It does the minimum amount of work it can get away with, and the relayed data may
/// be technically invalid. For example, all generated transactions share the same dummy
/// input uxto.
#[derive(Clone)]
pub struct MockBitcoinCore {
    parachain_rpc: Arc<InterBtcParachain>,
    blocks: Arc<RwLock<Vec<Block>>>,
    mempool: Arc<RwLock<Vec<Transaction>>>,
    transaction_creation_lock: Arc<Mutex<()>>,
}

impl MockBitcoinCore {
    /// Creates a new instance, and initializes parachain's btc-relay
    pub async fn new(parachain_rpc: InterBtcParachain) -> Self {
        let ret = Self {
            parachain_rpc: Arc::new(parachain_rpc),
            blocks: Arc::new(RwLock::new(vec![])),
            mempool: Arc::new(RwLock::new(vec![])),
            transaction_creation_lock: Arc::new(Mutex::new(())),
        };

        let address = BtcAddress::P2PKH(H160::from([0; 20]))
            .to_address(Network::Regtest)
            .unwrap();
        let dummy_tx = Self::generate_normal_transaction(&address, 10000);
        let block = ret.generate_block_with_transaction(&dummy_tx).await;
        let raw_block_header = serialize(&block.header);
        ret.parachain_rpc
            .initialize_btc_relay(RawBlockHeader(raw_block_header), 0)
            .await
            .expect("failed to initialize relay");

        // submit blocks in order to prevent the WaitingForRelayerInitialization error in request_issue
        let headers = futures::future::join_all((0..7u32).map(|_| ret.generate_block_with_transaction(&dummy_tx)))
            .await
            .into_iter()
            .map(|x| RawBlockHeader(serialize(&x.header)))
            .collect::<Vec<_>>();

        ret.parachain_rpc.store_block_headers(headers).await.unwrap();

        ret
    }

    pub async fn find_transaction(&self, f: impl Fn(&Transaction) -> bool) -> Option<Transaction> {
        self.blocks
            .read()
            .await
            .iter()
            .find_map(|block| block.txdata.iter().find(|x| f(x)))
            .cloned()
    }

    /// Creates a new instance, but does not initializes parachain's btc-relay
    pub async fn new_uninitialized(parachain_rpc: InterBtcParachain) -> Self {
        Self {
            parachain_rpc: Arc::new(parachain_rpc),
            blocks: Arc::new(RwLock::new(vec![])),
            mempool: Arc::new(RwLock::new(vec![])),
            transaction_creation_lock: Arc::new(Mutex::new(())),
        }
    }

    /// creates a fork
    pub fn enable_forking_test() {}

    /// relay a given block to the parachain
    async fn send_block(&self, block: Block) {
        let raw_block_header = serialize(&block.header);
        self.parachain_rpc
            .store_block_header(RawBlockHeader(raw_block_header))
            .await
            .unwrap();
    }

    async fn generate_block_with_transaction(&self, transaction: &Transaction) -> Block {
        let target = U256::from(2).pow(254.into());
        let mut bytes = [0u8; 32];
        target.to_big_endian(&mut bytes);
        let target = Target::from_be_bytes(bytes);
        let mut blocks = self.blocks.write().await;

        let prev_blockhash = if blocks.is_empty() {
            BlockHash::all_zeros()
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
                version: Version::from_consensus(4),
                merkle_root: TxMerkleNode::all_zeros(),
                bits: target.to_compact_lossy(),
                nonce: 0,
                prev_blockhash,
                time: 1,
            },
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();

        loop {
            if block.header.validate_pow(target).is_ok() {
                break;
            }
            block.header.nonce += 1;
        }

        blocks.push(block.clone());

        block
    }

    fn generate_normal_transaction(address: &Address, reward: u64) -> Transaction {
        let address = ScriptBuf::from(address.payload.script_pubkey().as_bytes().to_vec());

        let return_to_self_address = BtcAddress::P2PKH(H160::from_slice(&[20; 20]));
        let return_to_self_address = ScriptBuf::from(return_to_self_address.to_script_pub_key().as_bytes().to_vec());

        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint {
                    // random txid as input: it is not checked anyway. We ony need to make sure
                    // it is not equal to Outpoint::null, because that would be treated as a
                    // coinbase transaction
                    txid: Txid::from_slice(&[1; 32]).unwrap(),
                    vout: 0,
                },
                witness: Witness::from_slice::<&[u8]>(&[]),
                // actual contents of don't script_sig don't really matter as long as it contains
                // a parsable script
                script_sig: ScriptBuf::from(vec![
                    0, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234, 210, 186, 21, 187, 98,
                    38, 255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123, 216, 232, 168, 2, 32, 72, 126, 179, 207,
                    142, 8, 99, 8, 32, 78, 244, 166, 106, 160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12,
                    194, 240, 212, 3, 120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247,
                    165, 78, 111, 80, 79, 50, 200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253, 134, 127, 212, 51,
                    33, 2, 128, 200, 184, 235, 148, 25, 43, 34, 28, 173, 55, 54, 189, 164, 187, 243, 243, 152, 7, 84,
                    210, 85, 156, 238, 77, 97, 188, 240, 162, 197, 105, 62, 82, 174,
                ]),
                // not checked
                sequence: Sequence(0),
            }],
            output: vec![
                TxOut {
                    script_pubkey: address,
                    value: reward,
                },
                TxOut {
                    script_pubkey: return_to_self_address,
                    value: 42,
                },
            ],
            lock_time: LockTime::ZERO,
            version: 2,
        }
    }

    fn generate_coinbase_transaction(address: &BtcAddress, reward: u64, height: u32) -> Transaction {
        let address = ScriptBuf::from(address.to_script_pub_key().as_bytes().to_vec());

        // construct height: see https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
        // first byte is number of bytes in the number (will be 0x03 on main net for the next
        // 150 or so years with 223-1 blocks), following bytes are little-endian representation
        // of the number (including a sign bit)
        let mut height_bytes = height.to_le_bytes().to_vec();
        for i in (1..4).rev() {
            // remove trailing zeroes, but always keep first byte even if it's zero
            if height_bytes[i] == 0 {
                height_bytes.remove(i);
            } else {
                break;
            }
        }
        height_bytes.insert(0, height_bytes.len() as u8);

        // note that we set lock_time to height, otherwise we might generate blocks with
        // identical block hashes
        Transaction {
            input: vec![TxIn {
                previous_output: OutPoint::null(), // coinbase
                witness: Witness::from_slice::<&[u8]>(&[]),
                script_sig: ScriptBuf::from(height_bytes),
                sequence: Sequence(u32::max_value()),
            }],
            output: vec![TxOut {
                script_pubkey: address,
                value: reward,
            }],
            lock_time: LockTime::Blocks(Height::from_consensus(height).unwrap()),
            version: 2,
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

    async fn create_transaction_with_many_inputs(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
    ) -> Result<Transaction, BitcoinError> {
        let mut transaction = MockBitcoinCore::generate_normal_transaction(&address, sat);

        for _ in 1..100 {
            // add an output with the op_return to the transaction
            let mut op_return_script = vec![0x6a, 32];
            op_return_script.append(&mut vec![0; 32]);
            let op_return = TxOut {
                value: 0,
                script_pubkey: ScriptBuf::from(op_return_script),
            };
            transaction.output.insert(0, op_return.clone());
        }

        if let Some(request_id) = request_id {
            // add an output with the op_return to the transaction
            let mut op_return_script = vec![0x6a, 32];
            op_return_script.append(&mut request_id.to_fixed_bytes().to_vec());
            let op_return = TxOut {
                value: 0,
                script_pubkey: ScriptBuf::from(op_return_script),
            };
            transaction.output.push(op_return);
        }

        Ok(transaction)
    }

    pub async fn send_to_address_with_many_outputs(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
        fee_rate: SatPerVbyte,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let tx = self
            .create_transaction_with_many_inputs(address, sat, request_id)
            .await?;
        let txid = self.send_transaction(&tx).await?;
        let metadata = self
            .wait_for_transaction_metadata(txid, num_confirmations)
            .await
            .unwrap();
        Ok(metadata)
    }

    async fn send_transaction(&self, transaction: &Transaction) -> Result<Txid, BitcoinError> {
        let block = self.generate_block_with_transaction(transaction).await;
        self.send_block(block.clone()).await;
        Ok(transaction.txid())
    }

    pub async fn create_transaction(
        &self,
        address: Address,
        sat: u64,
        _fee_rate: SatPerVbyte, // ignored in this impl
        request_id: Option<H256>,
    ) -> Result<Transaction, BitcoinError> {
        let mut transaction = MockBitcoinCore::generate_normal_transaction(&address, sat);

        if let Some(request_id) = request_id {
            // add an output with the op_return to the transaction
            let mut op_return_script = vec![0x6a, 32];
            op_return_script.append(&mut request_id.to_fixed_bytes().to_vec());
            let op_return = TxOut {
                value: 0,
                script_pubkey: ScriptBuf::from(op_return_script),
            };
            transaction.output.push(op_return);
        }

        Ok(transaction)
    }
}

#[async_trait]
impl BitcoinCoreApi for MockBitcoinCore {
    fn network(&self) -> Network {
        Network::Regtest
    }
    async fn wait_for_block(&self, height: u32, _num_confirmations: u32) -> Result<Block, BitcoinError> {
        loop {
            let blocks = self.blocks.read().await;
            if let Some(block) = blocks.get(height as usize + 1) {
                return Ok(block.clone());
            }
            drop(blocks); // release the lock
            sleep(Duration::from_secs(1)).await;
        }
    }
    fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError> {
        Ok(Amount::ZERO)
    }
    fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError> {
        Ok(vec![])
    }
    fn list_addresses(&self) -> Result<Vec<Address>, BitcoinError> {
        Ok(vec![])
    }
    async fn get_block_count(&self) -> Result<u64, BitcoinError> {
        Ok((self.blocks.read().await.len() - 1).try_into().unwrap())
    }
    async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError> {
        let transaction = self.get_transaction(txid, Some(*block_hash)).await?;
        Ok(serialize(&transaction))
    }
    async fn get_transaction(&self, txid: &Txid, _block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError> {
        self.blocks
            .read()
            .await
            .iter()
            .find_map(|x| x.txdata.iter().find(|y| &y.txid() == txid))
            .ok_or(BitcoinError::InvalidBitcoinHeight)
            .cloned()
    }

    async fn get_proof(&self, txid: Txid, _block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError> {
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
        assert_eq!(txids.len(), 2); // expect coinbase and user tx

        let partial_merkle_tree = if txids[0] == txid {
            PartialMerkleTree::from_txids(&txids, &[true, false])
        } else if txids[1] == txid {
            PartialMerkleTree::from_txids(&txids, &[false, true])
        } else {
            panic!("txid not in block")
        };

        proof.append(&mut serialize(&partial_merkle_tree));

        Ok(proof)
    }
    async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        let block = blocks.get(height as usize).ok_or(BitcoinError::InvalidBitcoinHeight)?;
        Ok(block.header.block_hash())
    }

    async fn get_new_address(&self) -> Result<Address, BitcoinError> {
        let bytes: [u8; 20] = (0..20)
            .map(|_| thread_rng().gen::<u8>())
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
            .unwrap();
        let address = BtcAddress::P2PKH(H160::from(bytes));
        Ok(address.to_address(Network::Regtest)?)
    }
    async fn get_new_public_key(&self) -> Result<PublicKey, BitcoinError> {
        let secp = Secp256k1::new();
        let raw_secret_key: [u8; SECRET_KEY_SIZE] = thread_rng().gen();
        let secret_key = SecretKey::from_slice(&raw_secret_key).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        Ok(PublicKey::new(public_key))
    }
    fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, BitcoinError> {
        todo!()
    }
    fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), BitcoinError> {
        todo!()
    }
    async fn add_new_deposit_key(&self, _public_key: PublicKey, _secret_key: Vec<u8>) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError> {
        let blocks = self.blocks.read().await;
        Ok(blocks[blocks.len() - 1].block_hash())
    }
    async fn get_pruned_height(&self) -> Result<u64, BitcoinError> {
        Ok(0)
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
        Ok(block.header)
    }
    async fn get_mempool_transactions<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError> {
        let transactions = (*self.mempool.read().await).clone();
        Ok(Box::new(transactions.into_iter().map(Ok)))
    }
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        _num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let (block_height, block) = loop {
            // we have to be careful not to deadlock, so limit the scope of the lock
            let blocks = (*self.blocks.read().await).clone();

            if let Some(x) = blocks.iter().enumerate().find(|x| x.1.txdata[1].txid() == txid) {
                break (x.0, x.1.clone());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        };
        let block_hash = block.block_hash();
        let coinbase_txid = block.coinbase().unwrap().txid();
        let coinbase_tx_proof = self.get_proof(coinbase_txid, &block_hash).await.unwrap();
        let raw_coinbase_tx = self.get_raw_tx(&coinbase_txid, &block_hash).await.unwrap();
        let user_tx_proof = self.get_proof(txid, &block_hash).await.unwrap();
        let raw_user_tx = self.get_raw_tx(&txid, &block_hash).await.unwrap();

        Ok(TransactionMetadata {
            block_hash,
            proof: RawTransactionProof {
                user_tx_proof,
                raw_user_tx,
                coinbase_tx_proof,
                raw_coinbase_tx,
            },
            txid,
            block_height: block_height as u32,
            fee: None,
        })
    }
    async fn create_and_send_transaction(
        &self,
        address: Address,
        sat: u64,
        fee_rate: SatPerVbyte,
        request_id: Option<H256>,
    ) -> Result<Txid, BitcoinError> {
        let tx = self.create_transaction(address, sat, fee_rate, request_id).await?;
        let txid = self.send_transaction(&tx).await?;
        Ok(txid)
    }
    async fn send_to_address(
        &self,
        address: Address,
        sat: u64,
        request_id: Option<H256>,
        fee_rate: SatPerVbyte,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, BitcoinError> {
        let txid = self
            .create_and_send_transaction(address, sat, fee_rate, request_id)
            .await
            .unwrap();
        let metadata = self
            .wait_for_transaction_metadata(txid, num_confirmations)
            .await
            .unwrap();
        Ok(metadata)
    }
    async fn create_or_load_wallet(&self) -> Result<(), BitcoinError> {
        Ok(())
    }
    async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), BitcoinError> {
        Ok(())
    }

    async fn rescan_electrs_for_addresses(&self, addresses: Vec<Address>) -> Result<(), BitcoinError> {
        Ok(())
    }
    fn get_utxo_count(&self) -> Result<usize, BitcoinError> {
        Ok(0)
    }

    async fn bump_fee(&self, txid: &Txid, address: Address, fee_rate: SatPerVbyte) -> Result<Txid, BitcoinError> {
        unimplemented!()
    }

    async fn is_in_mempool(&self, txid: Txid) -> Result<bool, BitcoinError> {
        unimplemented!()
    }

    async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, BitcoinError> {
        unimplemented!()
    }

    async fn get_tx_for_op_return(
        &self,
        _address: Address,
        _amount: u128,
        _data: H256,
    ) -> Result<Option<Txid>, BitcoinError> {
        Ok(None)
    }
}
