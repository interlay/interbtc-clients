use bitcoin::BlockHash;
use runtime::{BtcRelayPallet, H256Le, PolkaBtcProvider};
use std::time::Duration;
use tokio::time::delay_for;

const BLOCK_WAIT_TIMEOUT: u64 = 6;

pub async fn wait_for_block_in_relay(provider: &PolkaBtcProvider, block_hash: BlockHash) {
    loop {
        if let Ok(rich_block_header) = provider
            .get_block_header(H256Le::from_bytes_le(&block_hash.to_vec()))
            .await
        {
            if rich_block_header.block_height > 0 {
                return;
            }
        }
        delay_for(Duration::from_secs(BLOCK_WAIT_TIMEOUT)).await;
    }
}
