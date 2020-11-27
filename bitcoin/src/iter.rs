use crate::{BitcoinCoreApi, Error};
use bitcoincore_rpc::{
    bitcoin::{Block, Transaction},
    json::GetBlockResult,
};
use std::iter;
use std::sync::Arc;

/// Iterate over transactions, starting with transactions in the mempool, and continuing
/// with transactions from the best in-chain block, and stopping after the block at
/// `stop_height` has been returned.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return transactions from
pub fn get_transactions<T: BitcoinCoreApi>(
    rpc: Arc<T>,
    stop_height: u32,
) -> Result<impl Iterator<Item = Result<Transaction, Error>>, Error> {
    let mempool_transactions = rpc.clone().get_mempool_transactions()?;
    let in_chain_transactions = get_in_chain_transactions(rpc, stop_height);
    Ok(mempool_transactions.chain(in_chain_transactions))
}

/// Iterate over every transaction in every block returned by `get_blocks`.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return transactions from
pub fn get_in_chain_transactions<T: BitcoinCoreApi>(
    rpc: Arc<T>,
    stop_height: u32,
) -> impl Iterator<Item = Result<Transaction, Error>> {
    get_blocks(rpc, stop_height).flat_map(|block| {
        // unfortunately two different iterators don't have compatible types, so we have
        // to box them to trait objects
        let transactions: Box<dyn Iterator<Item = _>> = match block {
            Ok(e) => Box::new(e.txdata.into_iter().map(|x| Ok(x))),
            Err(e) => Box::new(iter::once(Err(e))),
        };
        transactions
    })
}

/// Iterate over blocks, start at the best_best, stop at `stop_height`. Note:
/// the best block is determined when `next()` is first called on the iterator.
/// This prevents problems when a new block was added while we were iterating
/// over mempool transactions.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return
pub fn get_blocks<T: BitcoinCoreApi>(
    rpc: Arc<T>,
    stop_height: u32,
) -> impl Iterator<Item = Result<Block, Error>> {
    let mut state: Option<(usize, Block)> = None;
    iter::from_fn(move || {
        // get height and hash of the block we potentially are about to fetch
        let (next_height, next_hash) = match &state {
            Some((height, block)) => (height - 1, block.header.prev_blockhash),
            None => match get_best_block_info(rpc.clone()) {
                Ok(info) => (info.height, info.hash),
                Err(e) => return Some(Err(e)), // abort
            },
        };

        if next_height < stop_height as usize {
            None
        } else {
            match rpc.get_block(&next_hash) {
                Ok(block) => {
                    state = Some((next_height, block.clone()));
                    Some(Ok(block))
                }
                Err(e) => Some(Err(e)),
            }
        }
    })
}

/// small helper function for getting the block info of the best block. This simplifies
/// error handling a little bit
fn get_best_block_info<T: BitcoinCoreApi>(rpc: Arc<T>) -> Result<GetBlockResult, Error> {
    let hash = rpc.get_best_block_hash()?;
    rpc.get_block_info(&hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    pub use bitcoincore_rpc::bitcoin::TxMerkleNode;

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

            fn get_mempool_transactions<'a>(
                self: Arc<Self>,
            ) -> Result<Box<dyn Iterator<Item = Result<Transaction, Error>> + 'a>, Error>;

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

    fn dummy_block_info(height: usize, hash: BlockHash) -> GetBlockResult {
        GetBlockResult {
            height,
            hash,
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

    fn dummy_tx(value: i32) -> Transaction {
        Transaction {
            version: value,
            lock_time: 1,
            input: vec![],
            output: vec![],
        }
    }

    fn dummy_block(transactions: Vec<i32>, next_hash: BlockHash) -> Block {
        Block {
            txdata: transactions.into_iter().map(dummy_tx).collect(),
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
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![Ok(dummy_tx(0))].into_iter())));
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
            .returning(|&hash| Ok(dummy_block_info(21, hash)));

        let btc_rpc = Arc::new(bitcoin);
        let mut iter = get_transactions(btc_rpc, 20).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 0);
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
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
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
            .returning(|&hash| Ok(dummy_block_info(23, hash)));

        let btc_rpc = Arc::new(bitcoin);
        let mut iter = get_transactions(btc_rpc, 20).unwrap();

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
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = Arc::new(bitcoin);

        let mut iter = get_transactions(btc_rpc, 21).unwrap();

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_transaction_iterator_always_iterates_over_mempool() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![Ok(dummy_tx(1)), Ok(dummy_tx(2))].into_iter())));
        bitcoin
            .expect_get_best_block_hash()
            .returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = Arc::new(bitcoin);

        let mut iter = get_transactions(btc_rpc, 21).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 1);
        assert_eq!(iter.next().unwrap().unwrap().version, 2);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_transaction_iterator_can_have_start_equal_to_height() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
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
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = Arc::new(bitcoin);

        let mut iter = get_transactions(btc_rpc, 20).unwrap();

        assert_eq!(iter.next().unwrap().unwrap().version, 1);
        assert!(iter.next().is_none());
    }
}
