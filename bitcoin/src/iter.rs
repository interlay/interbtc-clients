use crate::{BitcoinCoreApi, Error};
use bitcoincore_rpc::{
    bitcoin::{Block, BlockHash, Transaction},
    json::GetBlockResult,
};
use futures::{prelude::*, stream::StreamExt};
use log::trace;
use std::iter;

/// Stream over transactions, starting with this in the mempool and continuing with
/// transactions from previous in-chain block. The stream ends after the block at
/// `stop_height` has been returned.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return transactions from
pub async fn reverse_stream_transactions<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    rpc: &B,
    stop_height: u32,
) -> Result<impl Stream<Item = Result<Transaction, Error>> + Unpin + '_, Error> {
    let mempool_transactions = stream::iter(rpc.get_mempool_transactions().await?);
    let in_chain_transactions = reverse_stream_in_chain_transactions(rpc, stop_height).await;
    Ok(mempool_transactions.chain(in_chain_transactions))
}

/// Stream every transaction in every block returned by `reverse_stream_blocks`.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return transactions from
pub async fn reverse_stream_in_chain_transactions<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    rpc: &B,
    stop_height: u32,
) -> impl Stream<Item = Result<Transaction, Error>> + Send + Unpin + '_ {
    reverse_stream_blocks(rpc, stop_height).await.flat_map(|block| {
        // unfortunately two different iterators don't have compatible types, so we have
        // to box them to trait objects
        let transactions: Box<dyn Stream<Item = _> + Unpin + Send> = match block {
            Ok(e) => Box::new(stream::iter(e.txdata.into_iter().map(Ok))),
            Err(e) => Box::new(stream::iter(iter::once(Err(e)))),
        };
        transactions
    })
}

/// Stream blocks in reverse order, starting at the current best height reported
/// by Bitcoin core. The best block is determined when `next()` is first called
/// on the stream. This prevents problems when a new block was added while we were
/// iterating over mempool transactions. The stream ends when the block at marked
/// as `stop_height` is resolved.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the stream will return
pub async fn reverse_stream_blocks<B: BitcoinCoreApi + Clone + Send + Sync + 'static>(
    rpc: &B,
    stop_height: u32,
) -> impl Stream<Item = Result<Block, Error>> + Unpin + '_ {
    struct StreamState<B> {
        height: Option<u32>,
        prev_block: Option<Block>,
        rpc: B,
        stop_height: u32,
    }

    let state = StreamState {
        height: None,
        prev_block: None,
        rpc,
        stop_height,
    };

    Box::pin(
        stream::unfold(state, |mut state| async {
            // get height and hash of the block we potentially are about to fetch
            let (next_height, next_hash) = match (&state.height, &state.prev_block) {
                (Some(height), Some(block)) => (height.saturating_sub(1), block.header.prev_blockhash),
                _ => match get_best_block_info(state.rpc).await {
                    Ok(info) => (info.height as u32, info.hash),
                    Err(e) => return Some((Err(e), state)), // abort
                },
            };

            let result = if next_height < state.stop_height {
                return None;
            } else {
                match state.rpc.get_block(&next_hash).await {
                    Ok(block) => {
                        state.height = Some(next_height);
                        state.prev_block = Some(block.clone());
                        Ok(block)
                    }
                    Err(e) => Err(e),
                }
            };
            Some((result, state))
        })
        .fuse(),
    )
}

/// Stream all transactions in blocks produced by Bitcoin Core.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `from_height` - height of the first block of the stream
/// * `num_confirmations` - minimum for a block to be accepted
pub async fn stream_in_chain_transactions<B: BitcoinCoreApi + Clone>(
    rpc: B,
    from_height: u32,
    num_confirmations: u32,
) -> impl Stream<Item = Result<(BlockHash, Transaction), Error>> + Unpin {
    Box::pin(
        stream_blocks(rpc, from_height, num_confirmations)
            .await
            .flat_map(|result| {
                futures::stream::iter(result.map_or_else(
                    |err| vec![Err(err)],
                    |block| {
                        let block_hash = block.block_hash();
                        block.txdata.into_iter().map(|tx| Ok((block_hash, tx))).collect()
                    },
                ))
            }),
    )
}

/// Stream blocks continuously `from_height` awaiting the production of
/// new blocks as reported by Bitcoin core. The stream never ends.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `from_height` - height of the first block of the stream
/// * `num_confirmations` - minimum for a block to be accepted
pub async fn stream_blocks<B: BitcoinCoreApi + Clone>(
    rpc: B,
    from_height: u32,
    num_confirmations: u32,
) -> impl Stream<Item = Result<Block, Error>> + Unpin {
    struct StreamState<B> {
        rpc: B,
        next_height: u32,
    }

    let state = StreamState {
        rpc,
        next_height: from_height,
    };

    Box::pin(
        stream::unfold(state, move |mut state| async move {
            // FIXME: if Bitcoin Core forks, this may skip a block
            let height = state.next_height;
            match state.rpc.wait_for_block(height, num_confirmations).await {
                Ok(block) => {
                    trace!("found block {} at height {}", block.block_hash(), height);
                    state.next_height += 1;
                    Some((Ok(block), state))
                }
                Err(e) => Some((Err(e), state)),
            }
        })
        .fuse(),
    )
}

/// small helper function for getting the block info of the best block. This simplifies
/// error handling a little bit
async fn get_best_block_info<B: BitcoinCoreApi + Clone>(rpc: &B) -> Result<GetBlockResult, Error> {
    let hash = rpc.get_best_block_hash().await?;
    rpc.get_block_info(&hash).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    pub use bitcoincore_rpc::bitcoin::{Amount, Network, TxMerkleNode};
    use sp_core::H256;

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, Error>;
            async fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error>;
            async fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, Error>;
            async fn get_block_count(&self) -> Result<u64, Error>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, Error>;
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
            async fn create_and_send_transaction<A: PartialAddress + Send + 'static>(
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
            async fn get_utxo_count(&self) -> Result<usize, Error>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
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
                version: 4,
                bits: 0,
                nonce: 0,
                time: 0,
                prev_blockhash: next_hash,
                merkle_root: TxMerkleNode::default(),
            },
        }
    }

    #[tokio::test]
    async fn test_transaction_iterator_succeeds() {
        // we abuse version number within the transaction to check whether the sequence is correct

        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![Ok(dummy_tx(0))].into_iter())));
        bitcoin.expect_get_best_block_hash().returning(|| Ok(dummy_hash(1)));
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

        let btc_rpc = bitcoin;
        let mut iter = reverse_stream_transactions(&btc_rpc, 20).await.unwrap();

        assert_eq!(iter.next().await.unwrap().unwrap().version, 0);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 1);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 2);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 3);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 4);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 5);
        assert!(iter.next().await.is_none());
        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn test_transaction_iterator_skips_over_empty_blocks() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
        bitcoin.expect_get_best_block_hash().returning(|| Ok(dummy_hash(1)));
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

        let btc_rpc = bitcoin;
        let mut iter = reverse_stream_transactions(&btc_rpc, 20).await.unwrap();

        assert_eq!(iter.next().await.unwrap().unwrap().version, 1);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 2);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 3);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 4);
        assert!(iter.next().await.is_none());
        assert!(iter.next().await.is_none());
    }
    #[tokio::test]
    async fn test_transaction_iterator_can_have_invalid_height() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
        bitcoin.expect_get_best_block_hash().returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = bitcoin;

        let mut iter = reverse_stream_transactions(&btc_rpc, 21).await.unwrap();

        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn test_transaction_iterator_always_iterates_over_mempool() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![Ok(dummy_tx(1)), Ok(dummy_tx(2))].into_iter())));
        bitcoin.expect_get_best_block_hash().returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = bitcoin;

        let mut iter = reverse_stream_transactions(&btc_rpc, 21).await.unwrap();

        assert_eq!(iter.next().await.unwrap().unwrap().version, 1);
        assert_eq!(iter.next().await.unwrap().unwrap().version, 2);
        assert!(iter.next().await.is_none());
    }

    #[tokio::test]
    async fn test_transaction_iterator_can_have_start_equal_to_height() {
        let mut bitcoin = MockBitcoin::default();
        bitcoin
            .expect_get_mempool_transactions()
            .times(1)
            .returning(|| Ok(Box::new(vec![].into_iter())));
        bitcoin.expect_get_best_block_hash().returning(|| Ok(dummy_hash(1)));
        bitcoin
            .expect_get_block()
            .withf(|&x| x == dummy_hash(1))
            .times(1)
            .returning(|_| Ok(dummy_block(vec![1], dummy_hash(2))));
        bitcoin
            .expect_get_block_info()
            .times(1)
            .returning(|&hash| Ok(dummy_block_info(20, hash)));

        let btc_rpc = bitcoin;

        let mut iter = reverse_stream_transactions(&btc_rpc, 20).await.unwrap();

        assert_eq!(iter.next().await.unwrap().unwrap().version, 1);
        assert!(iter.next().await.is_none());
    }
}
