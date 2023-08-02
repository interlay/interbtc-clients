use crate::{BitcoinCoreApi, BitcoinRpcError, Error};
use bitcoincore_rpc::{
    bitcoin::{Block, BlockHash, Transaction},
    jsonrpc::Error as JsonRpcError,
    Error as BitcoinError,
};
use futures::{prelude::*, stream::StreamExt};
use log::trace;
use std::{iter, sync::Arc};

type DynBitcoinCoreApi = Arc<dyn BitcoinCoreApi + Send + Sync>;

/// Stream over transactions, starting with this in the mempool and continuing with
/// transactions from previous in-chain block. The stream ends after the block at
/// `stop_height` has been returned.
///
/// # Arguments:
///
/// * `rpc` - bitcoin rpc
/// * `stop_height` - height of the last block the iterator will return transactions from
pub async fn reverse_stream_transactions(
    rpc: &DynBitcoinCoreApi,
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
/// * `stop_at_pruned` - whether to gracefully stop if a pruned blockchain is encountered;
/// otherwise, will throw an error
async fn reverse_stream_in_chain_transactions(
    rpc: &DynBitcoinCoreApi,
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
/// * `stop_at_pruned` - whether to gracefully stop if a pruned blockchain is encountered;
/// otherwise, will throw an error
async fn reverse_stream_blocks(
    rpc: &DynBitcoinCoreApi,
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
                    Ok((height, hash)) => (height, hash),
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
                    Err(Error::BitcoinError(BitcoinError::JsonRpc(JsonRpcError::Rpc(err))))
                        if BitcoinRpcError::from(err.clone()) == BitcoinRpcError::RpcMiscError =>
                    {
                        return None; // pruned block
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
pub async fn stream_in_chain_transactions(
    rpc: DynBitcoinCoreApi,
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
pub async fn stream_blocks(
    rpc: DynBitcoinCoreApi,
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
async fn get_best_block_info(rpc: &DynBitcoinCoreApi) -> Result<(u32, BlockHash), Error> {
    let height = rpc.get_block_count().await? as u32;
    let hash = rpc.get_block_hash(height).await?;
    Ok((height, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use bitcoincore_rpc::bitcoin::{absolute::Height, block::Version, locktime::absolute::LockTime, CompactTarget};
    pub use bitcoincore_rpc::bitcoin::{Address, Amount, Network, PublicKey};
    use sp_core::H256;

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            fn is_full_node(&self) -> bool;
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, Error>;
            fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, Error>;
            fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, Error>;
            fn list_addresses(&self) -> Result<Vec<Address>, Error>;
            async fn get_block_count(&self) -> Result<u64, Error>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, Error>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, Error>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, Error>;
            async fn get_new_address(&self) -> Result<Address, Error>;
            async fn get_new_public_key(&self) -> Result<PublicKey, Error>;
            fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, Error>;
            fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), Error>;
            async fn add_new_deposit_key(
                &self,
                public_key: PublicKey,
                secret_key: Vec<u8>,
            ) -> Result<(), Error>;
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
            async fn create_or_load_wallet(&self) -> Result<(), Error>;
            async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), Error>;
            async fn rescan_electrs_for_addresses(
                &self,
                addresses: Vec<Address>,
            ) -> Result<(), Error>;
            fn get_utxo_count(&self) -> Result<usize, Error>;
            async fn bump_fee(
                &self,
                txid: &Txid,
                address: Address,
                fee_rate: SatPerVbyte,
            ) -> Result<Txid, Error>;
            async fn is_in_mempool(&self, txid: Txid) -> Result<bool, Error>;
            async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, Error>;
            async fn get_tx_for_op_return(&self, address: Address, amount: u128, data: H256) -> Result<Option<Txid>, Error>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn dummy_hash(value: u8) -> BlockHash {
        BlockHash::from_slice(&[value; 32]).unwrap()
    }

    fn dummy_tx(value: i32) -> Transaction {
        Transaction {
            version: value,
            lock_time: LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        }
    }

    fn dummy_block(transactions: Vec<i32>, next_hash: BlockHash) -> Block {
        Block {
            txdata: transactions.into_iter().map(dummy_tx).collect(),
            header: BlockHeader {
                version: Version::from_consensus(2),
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
                time: 0,
                prev_blockhash: next_hash,
                merkle_root: TxMerkleNode::all_zeros(),
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
        bitcoin.expect_get_block_count().times(1).returning(|| Ok(21));
        bitcoin
            .expect_get_block_hash()
            .times(1)
            .returning(|_| Ok(dummy_hash(1)));

        let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin);
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
        bitcoin.expect_get_block_count().times(1).returning(|| Ok(23));
        bitcoin
            .expect_get_block_hash()
            .times(1)
            .returning(|_| Ok(dummy_hash(1)));

        let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin);
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
        bitcoin.expect_get_block_count().times(1).returning(|| Ok(20));
        bitcoin
            .expect_get_block_hash()
            .times(1)
            .returning(|_| Ok(dummy_hash(1)));

        let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin);
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
        bitcoin.expect_get_block_count().times(1).returning(|| Ok(20));
        bitcoin
            .expect_get_block_hash()
            .times(1)
            .returning(|_| Ok(dummy_hash(1)));

        let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin);
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
        bitcoin.expect_get_block_count().times(1).returning(|| Ok(20));
        bitcoin
            .expect_get_block_hash()
            .times(1)
            .returning(|_| Ok(dummy_hash(1)));

        let btc_rpc: DynBitcoinCoreApi = Arc::new(bitcoin);
        let mut iter = reverse_stream_transactions(&btc_rpc, 20).await.unwrap();

        assert_eq!(iter.next().await.unwrap().unwrap().version, 1);
        assert!(iter.next().await.is_none());
    }
}
