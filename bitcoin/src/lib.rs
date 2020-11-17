#[cfg(feature = "cli")]
pub mod cli;

mod error;

use rand::{self, Rng};
use async_trait::async_trait;
use backoff::{future::FutureOperation as _, ExponentialBackoff};
pub use bitcoincore_rpc::{
    bitcoin::{
        blockdata::opcodes::all as opcodes,
        blockdata::script::Builder,
        consensus::encode::serialize,
        hash_types::BlockHash,
        hashes::{hex::ToHex, Hash},
        util::{address::Payload, psbt::serialize::Serialize},
        Address, Amount, Block, BlockHeader, Network, Transaction, TxOut, Txid,
    },
    bitcoincore_rpc_json::{GetRawTransactionResult, GetTransactionResult, WalletTxInfo},
    json::{self, GetBlockResult},
    jsonrpc::Error as JsonRpcError,
    Auth, Client, Error as BitcoinError, RpcApi,
};
pub use error::{ConversionError, Error};
use sp_core::{H160, H256};
use std::sync::Arc;
use std::{collections::HashMap, str::FromStr, time::Duration};
use tokio::time::delay_for;

pub struct TransactionMetadata {
    pub txid: Txid,
    pub proof: Vec<u8>,
    pub raw_tx: Vec<u8>,
    pub block_height: u32,
    pub block_hash: BlockHash,
}

#[async_trait]
pub trait BitcoinCoreApi {
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error>;

    fn get_block_count(&self) -> Result<u64, Error>;

    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error>;

    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;

    fn get_new_address(&self) -> Result<H160, Error>;

    fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

    fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

    fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error>;

    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;

    async fn send_to_address(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error>;
}

pub struct BitcoinCore {
    rpc: Client,
}

impl BitcoinCore {
    pub fn new(rpc: Client) -> Self {
        Self { rpc }
    }
}

#[async_trait]
impl BitcoinCoreApi for BitcoinCore {
    /// Wait for a specified height to return a `BlockHash` or
    /// exit on error.
    ///
    /// # Arguments
    /// * `height` - block height to fetch
    /// * `delay` - wait period before re-checking
    async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error> {
        loop {
            match self.rpc.get_block_hash(height.into()) {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    delay_for(delay).await;
                    if let BitcoinError::JsonRpc(JsonRpcError::Rpc(rpc_error)) = &e {
                        // https://github.com/bitcoin/bitcoin/blob/be3af4f31089726267ce2dbdd6c9c153bb5aeae1/src/rpc/protocol.h#L43
                        if rpc_error.code == -8 {
                            continue;
                        }
                    }
                    return Err(e.into());
                }
            }
        }
    }

    /// Get the tip of the main chain as reported by Bitcoin core.
    fn get_block_count(&self) -> Result<u64, Error> {
        Ok(self.rpc.get_block_count()?)
    }

    /// Get all transactions in a block identified by the
    /// given hash.
    ///
    /// # Arguments
    /// * `hash` - block hash to query
    fn get_block_transactions(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<Option<GetRawTransactionResult>>, Error> {
        let info = self.rpc.get_block_info(hash)?;
        let txs = info
            .tx
            .iter()
            .map(
                |id| match self.rpc.get_raw_transaction_info(&id, Some(hash)) {
                    Ok(tx) => Some(tx),
                    // TODO: log error
                    Err(_) => None,
                },
            )
            .collect::<Vec<Option<GetRawTransactionResult>>>();
        Ok(txs)
    }

    /// Get the raw transaction identified by `Txid` and stored
    /// in the specified block.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(serialize(
            &self.rpc.get_raw_transaction(txid, Some(block_hash))?,
        ))
    }

    /// Get the merkle proof which can be used to validate transaction inclusion.
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `block_hash` - hash of the block tx is stored in
    fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error> {
        Ok(self.rpc.get_tx_out_proof(&[txid], Some(block_hash))?)
    }

    /// Get the block hash for a given height.
    ///
    /// # Arguments
    /// * `height` - block height
    fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_block_hash(height.into())?)
    }

    /// Checks if the local full node has seen the specified block hash.
    ///
    /// # Arguments
    /// * `block_hash` - hash of the block to verify
    fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error> {
        // TODO: match exact error
        Ok(self.rpc.get_block(&block_hash).is_ok())
    }

    /// Gets a new address from the wallet
    fn get_new_address(&self) -> Result<H160, Error> {
        let address = self.rpc.get_new_address(None, None)?;
        Ok(get_hash_from_string(&address.to_string())?)
    }

    fn get_best_block_hash(&self) -> Result<BlockHash, Error> {
        Ok(self.rpc.get_best_block_hash()?)
    }

    fn get_block(&self, hash: &BlockHash) -> Result<Block, Error> {
        Ok(self.rpc.get_block(hash)?)
    }

    fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error> {
        Ok(self.rpc.get_block_info(hash)?)
    }

    /// Waits for the required number of confirmations, and collects data about the
    /// transaction
    ///
    /// # Arguments
    /// * `txid` - transaction ID
    /// * `op_timeout` - wait period before re-checking
    /// * `op_timeout` - how long operations will be retried
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn wait_for_transaction_metadata(
        &self,
        txid: Txid,
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let get_retry_policy = || ExponentialBackoff {
            max_elapsed_time: Some(op_timeout),
            ..Default::default()
        };

        let (block_height, block_hash) = (|| async {
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
                }) if confirmations >= 0 && confirmations as u32 >= num_confirmations => {
                    Ok((height, hash))
                }
                Ok(_) => Err(Error::ConfirmationError),
                Err(e) => Err(e.into()),
            }?)
        })
        .retry(get_retry_policy())
        .await?;

        let proof = (|| async { Ok(self.get_proof_for(txid, &block_hash)?) })
            .retry(get_retry_policy())
            .await?;

        let raw_tx = (|| async { Ok(self.get_raw_tx_for(&txid, &block_hash)?) })
            .retry(get_retry_policy())
            .await?;

        Ok(TransactionMetadata {
            txid,
            block_hash,
            block_height,
            proof,
            raw_tx,
        })
    }

    /// Send an amount of Bitcoin to an address and wait until it has a confirmation.
    ///
    /// # Arguments
    /// * `address` - Bitcoin address to fund
    /// * `sat` - number of Satoshis to transfer
    /// * `redeem_id` - the redeemid for which this transfer is being made
    /// * `op_timeout` - how long operations will be retried
    /// * `num_confirmations` - how many confirmations we need to wait for
    async fn send_to_address(
        &self,
        address: String,
        sat: u64,
        redeem_id: &[u8; 32],
        op_timeout: Duration,
        num_confirmations: u32,
    ) -> Result<TransactionMetadata, Error> {
        let mut recipients = HashMap::<String, Amount>::new();
        recipients.insert(address.clone(), Amount::from_sat(sat));

        let delay = rand::thread_rng().gen_range(1000, 10000);
        delay_for(Duration::from_millis(delay)).await;

        let raw_tx = self
            .rpc
            .create_raw_transaction_hex(&[], &recipients, None, None)?;

        let funding_opts = json::FundRawTransactionOptions {
            fee_rate: Some(Amount::from_sat(10000)),
            ..Default::default()
        };

        let raw_tx = self
            .rpc
            .fund_raw_transaction(raw_tx, Some(&funding_opts), None)?;

        let mut tx = raw_tx.transaction().unwrap();

        fix_transaction_output_order(&mut tx, address)?;

        // include the redeem is in the transaction
        add_redeem_id(&mut tx, redeem_id);

        let signed_raw_tx =
            self.rpc
                .sign_raw_transaction_with_wallet(tx.serialize().to_hex(), None, None)?;

        let txid = self
            .rpc
            .send_raw_transaction(signed_raw_tx.transaction().unwrap().serialize().to_hex())?;

        #[cfg(feature = "regtest")]
        self.rpc
            .generate_to_address(1, &self.rpc.get_new_address(None, None)?)?;

        Ok(self
            .wait_for_transaction_metadata(txid, op_timeout, num_confirmations)
            .await?)
    }
}

/// Returns an iterator over bitcoin transactions that yields all transactions starting at the
/// most recent block, and stopping at `btc_start_height`
///
/// # Arguments
///
/// * `btc_start_height` - the oldest block to be yielded in the iterator
pub fn transactions<T: BitcoinCoreApi>(
    btc_rpc: Arc<T>,
    btc_start_height: u32,
) -> Result<TransactionIterator<T>, Error> {
    let starting_hash = btc_rpc.get_best_block_hash()?;
    let block = btc_rpc.get_block(&starting_hash)?;
    let info = btc_rpc.get_block_info(&starting_hash)?;

    // return the iterator
    let num_blocks = if info.height < btc_start_height as usize {
        0
    } else {
        info.height - btc_start_height as usize + 1
    };

    Ok(TransactionIterator {
        block,
        blocks_remaining: num_blocks,
        txdata_idx: 0,
        rpc: btc_rpc,
    })
}

/// Extension trait for transaction, adding methods to help to match the Transaction to Replace/Redeem requests
pub trait TransactionExt {
    fn get_op_return(&self) -> Option<H256>;
    fn get_payment_amount_to(&self, to: H160) -> Option<u64>;
}
impl TransactionExt for Transaction {
    /// Extract the hash from the OP_RETURN uxto, if present
    fn get_op_return(&self) -> Option<H256> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|x| {
            // match a slice that starts with op_return (0x6a), then has 32 as
            // the length indicator, and then has 32 bytes (the H256)
            match x.script_pubkey.to_bytes().as_slice() {
                [0x6a, 32, rest @ ..] if rest.len() == 32 => Some(H256::from_slice(rest)),
                _ => None,
            }
        })
    }

    /// Get the amount of btc that self sent to `destination`, if any
    fn get_payment_amount_to(&self, destination: H160) -> Option<u64> {
        // we only consider the first three items because the parachain only checks the first 3 positions
        self.output.iter().take(3).find_map(|uxto| {
            let payload = Payload::from_script(&uxto.script_pubkey)?;
            let hash = match payload {
                Payload::PubkeyHash(h) => H160::from_slice(h.as_hash().into_inner().as_ref()),
                Payload::ScriptHash(h) => H160::from_slice(h.as_hash().into_inner().as_ref()),
                Payload::WitnessProgram { version: _, program } => {
                    let program = program.as_slice();
                    // make sure the length is as we expect, otherwise H160::from_slice may panic
                    if program.len() != 20 {
                        return None;
                    }
                    H160::from_slice(program)
                }
            };
            if hash == destination {
                Some(uxto.value)
            } else {
                None
            }
        })
    }
}

/// Iterator over transactions in the bitcoin chain, from new-to-old. The number of
/// returned elements is limited by blocks_remaining.
pub struct TransactionIterator<T: BitcoinCoreApi> {
    block: Block,
    blocks_remaining: usize,
    txdata_idx: usize,
    rpc: Arc<T>,
}
impl<T: BitcoinCoreApi> Iterator for TransactionIterator<T> {
    type Item = Result<Transaction, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        // we already iterated over the set range
        if self.blocks_remaining == 0 {
            return None;
        }

        // if there are no transactions remaining in this block that we haven't reported yet,
        // we continue to the next block. By using `while` instead of `if` we can be 100% sure
        // the vec indexing can not panic in unexpected block inputs
        while self.txdata_idx >= self.block.txdata.len() {
            // we go to next block
            self.blocks_remaining -= 1;
            if self.blocks_remaining == 0 {
                return None; // no more blocks to be found
            }
            match self.rpc.get_block(&self.block.header.prev_blockhash) {
                Ok(x) => {
                    self.txdata_idx = 0;
                    self.block = x;
                }
                Err(x) => {
                    return Some(Err(x));
                }
            }
        }

        let ret = self.block.txdata[self.txdata_idx].clone();
        self.txdata_idx += 1;
        Some(Ok(ret))
    }
}

/// Ensures we follow the spec: the payment to the recipient needs to be the
/// first uxto. Funding the transaction sometimes places the return-to-self
/// uxto first, so this function performs a swap of uxtos if necessary
fn fix_transaction_output_order(
    tx: &mut Transaction,
    recipient_address: String,
) -> Result<(), Error> {
    let address_hash = get_hash_from_string(recipient_address.as_str())?;
    let recipient_raw = address_hash.as_bytes();
    let output0_addr = &tx.output[0].script_pubkey.as_bytes()[2..];

    if recipient_raw != output0_addr {
        // most likely the return-to-self output was put first
        if tx.output.len() > 1 && recipient_raw == &tx.output[1].script_pubkey.as_bytes()[2..] {
            tx.output.swap(0, 1);
        } else {
            // if this executes we have a bug in the code
            panic!("Could not find recipient address in bitcoin transaction");
        }
    }
    Ok(())
}

/// Adds op_return with the given id at index 1, occording to the redeem spec
fn add_redeem_id(tx: &mut Transaction, redeem_id: &[u8; 32]) {
    // Index 1: Data UTXO: OP_RETURN containing identifier
    tx.output.insert(
        1,
        TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::OP_RETURN)
                .push_slice(redeem_id)
                .into_script(),
        },
    );
}

pub fn get_hash_from_string(btc_address: &str) -> Result<H160, ConversionError> {
    let addr = Address::from_str(btc_address)?;
    match addr.payload {
        Payload::PubkeyHash(hash) => Ok(H160::from(hash.as_hash().into_inner())),
        Payload::ScriptHash(hash) => Ok(H160::from(hash.as_hash().into_inner())),
        Payload::WitnessProgram {
            version: _,
            program,
        } => {
            if program.len() == 20 {
                Ok(H160::from_slice(program.as_slice()))
            } else {
                Err(ConversionError::WitnessProgramError)
            }
        }
    }
}

pub fn get_address_from_hex(btc_address: &str) -> Result<H160, ConversionError> {
    let decoded = hex::decode(btc_address)?;
    Ok(H160::from_slice(decoded.as_slice()))
}

pub fn hash_to_p2wpkh(btc_address: H160, network: Network) -> Result<String, ConversionError> {
    let witness_script = Builder::new()
        .push_opcode(0.into())
        .push_slice(btc_address.as_bytes())
        .into_script();

    let payload =
        Payload::from_script(&witness_script).ok_or(ConversionError::WitnessProgramError)?;
    let address = Address { network, payload };

    Ok(address.to_string())
}

fn bytes_to_h160<B: AsRef<[u8]>>(bytes: B) -> H160 {
    let slice = bytes.as_ref();
    let mut result = [0u8; 20];
    result.copy_from_slice(slice);
    result.into()
}

pub fn is_p2sh2wpkh(data: Vec<u8>) -> bool {
    data.len() == 23 && data[0] == opcodes::OP_PUSHBYTES_22.into_u8()
}

pub fn extract_btc_addresses(tx: GetRawTransactionResult) -> Vec<H160> {
    tx.vin
        .into_iter()
        .filter_map(|vin| {
            if let Some(script_sig) = &vin.script_sig {
                // this always returns ok so should be safe to unwrap
                let script = script_sig.script().unwrap();
                let bytes = script.to_bytes();
                if script.is_p2sh() {
                    return Some(bytes_to_h160(bytes[2..22].to_vec()));
                } else if script.is_p2pkh() {
                    return Some(bytes_to_h160(bytes[3..23].to_vec()));
                } else if script.is_v0_p2wpkh() {
                    return Some(bytes_to_h160(bytes[2..22].to_vec()));
                } else if is_p2sh2wpkh(bytes.to_vec()) {
                    return Some(bytes_to_h160(bytes[3..23].to_vec()));
                }
            }
            None
        })
        .collect::<Vec<H160>>()
}

pub fn extract_op_returns(_tx: GetRawTransactionResult) -> Vec<Vec<u8>> {
    // TODO: filter transactions for op_return outputs
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoincore_rpc::{
        bitcoin::{hash_types::TxMerkleNode, Txid, Wtxid},
        bitcoincore_rpc_json::{GetRawTransactionResultVin, GetRawTransactionResultVinScriptSig},
    };
    use mockall::Sequence;

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, Error>;

            fn get_block_count(&self) -> Result<u64, Error>;

            fn get_block_transactions(
                &self,
                hash: &BlockHash,
            ) -> Result<Vec<Option<GetRawTransactionResult>>, Error>;

            fn get_raw_tx_for(
                &self,
                txid: &Txid,
                block_hash: &BlockHash,
            ) -> Result<Vec<u8>, Error>;

            fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;

            fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, Error>;

            fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, Error>;
            
            fn get_new_address(&self) -> Result<H160, Error>;

            fn get_best_block_hash(&self) -> Result<BlockHash, Error>;

            fn get_block(&self, hash: &BlockHash) -> Result<Block, Error>;

            fn get_block_info(&self, hash: &BlockHash) -> Result<GetBlockResult, Error>;

            async fn wait_for_transaction_metadata(
                &self,
                txid: Txid,
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, Error>;

            async fn send_to_address(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, Error>;
        }
    }

    #[test]
    fn test_hash_to_p2wpkh() {
        let addr = "bcrt1q6v2c7q7uv8vu6xle2k9ryfj3y3fuuy4rqnl50f";
        let addr_hash = get_hash_from_string(addr).unwrap();
        let rebuilt_addr = hash_to_p2wpkh(addr_hash, Network::Regtest).unwrap();
        assert_eq!(addr, rebuilt_addr);
    }

    #[test]
    fn test_tx_has_inputs() {
        let mut addr = H160::zero();
        addr.assign_from_slice(&hex::decode("4ef45ff516f84c62b09ad4f605f92abc103f916b").unwrap());

        assert_eq!(
            extract_btc_addresses(GetRawTransactionResult {
                in_active_chain: None,
                hex: vec![],
                txid: Txid::default(),
                hash: Wtxid::default(),
                size: 0,
                vsize: 0,
                version: 0,
                locktime: 0,
                vin: vec![GetRawTransactionResultVin {
                    sequence: 0,
                    coinbase: None,
                    txid: None,
                    vout: None,
                    script_sig: Some(GetRawTransactionResultVinScriptSig {
                        asm: "".to_string(),
                        hex: vec![
                            169, 20, 78, 244, 95, 245, 22, 248, 76, 98, 176, 154, 212, 246, 5, 249,
                            42, 188, 16, 63, 145, 107, 135
                        ],
                    }),
                    txinwitness: None,
                }],
                vout: vec![],
                blockhash: None,
                confirmations: None,
                time: None,
                blocktime: None,
            }),
            vec![addr]
        );
    }

    fn dummy_block_info(height: usize) -> GetBlockResult {
        GetBlockResult {
            height,
            hash: Default::default(),
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
        }
    }

    fn dummy_hash(value: u8) -> BlockHash {
        BlockHash::from_slice(&[value; 32]).unwrap()
    }

    fn dummy_block(transactions: Vec<i32>, next_hash: BlockHash) -> Block {
        Block {
            txdata: transactions
                .into_iter()
                .map(|x| Transaction {
                    version: x,
                    lock_time: 1,
                    input: vec![],
                    output: vec![],
                })
                .collect(),
            header: BlockHeader {
                version: 1,
                bits: 0,
                nonce: 0,
                time: 0,
                prev_blockhash: next_hash,
                merkle_root: TxMerkleNode::default(),
            },
        }
    }

    #[test]
    fn test_transaction_iterator_succeeds() {
        // we abuse version number within the transaction to check whether the sequence is correct

        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(1))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![1, 2], dummy_hash(2))));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(2))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![3, 4, 5], dummy_hash(3))));

        // block info: the head of the btc we give a height of 22
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|_| Ok(dummy_block_info(21)));

        let btc_rpc = Arc::new(bitcoin);
        let mut iter = transactions(btc_rpc, 20).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 1);
        assert_eq!(iter.next().unwrap().unwrap().version, 2);
        assert_eq!(iter.next().unwrap().unwrap().version, 3);
        assert_eq!(iter.next().unwrap().unwrap().version, 4);
        assert_eq!(iter.next().unwrap().unwrap().version, 5);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_transaction_iterator_skips_over_empty_blocks() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(1))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![1, 2], dummy_hash(2))));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(2))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![], dummy_hash(3))));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(3))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![3, 4], dummy_hash(4))));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(4))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![], dummy_hash(5))));

        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|_| Ok(dummy_block_info(23)));

        let btc_rpc = Arc::new(bitcoin);
        let mut iter = transactions(btc_rpc, 20).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 1);
        assert_eq!(iter.next().unwrap().unwrap().version, 2);
        assert_eq!(iter.next().unwrap().unwrap().version, 3);
        assert_eq!(iter.next().unwrap().unwrap().version, 4);
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }
    #[test]
    fn test_transaction_iterator_can_have_invalid_height() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(1))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![1, 2], dummy_hash(2))));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|_| Ok(dummy_block_info(20)));

        let btc_rpc = Arc::new(bitcoin);

        let mut iter = transactions(btc_rpc, 21).unwrap();

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_transaction_iterator_can_have_start_equal_to_height() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(1))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![1], dummy_hash(2))));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|_| Ok(dummy_block_info(20)));

        let btc_rpc = Arc::new(bitcoin);

        let mut iter = transactions(btc_rpc, 20).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 1);
        assert!(iter.next().is_none());
    }
}
