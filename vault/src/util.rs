use crate::error::Error;
use backoff::{future::FutureOperation as _, ExponentialBackoff};
use bitcoin::BitcoinCoreApi;
use log::{error, info};
use runtime::H256Le;
use sp_core::{H160, H256};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::delay_for;

// keep trying for 24 hours
const MAX_RETRYING_TIME: Duration = Duration::from_secs(24 * 60 * 60);

/// First makes bitcoin transfer, then calls tries to call on_payment until it
/// succeeds
///
/// # Arguments
///
/// * `btc_rpc` - the bitcoin RPC handle
/// * `num_confirmations` - the number of bitcoin confirmation to await
/// * `btc_address` the destination address
/// * `amount_polka_btc` amount of btc to send
/// * `event_id` the nonce to incorporate with op_return into the transaction
/// * `network` network the bitcoin network used (i.e. regtest/testnet/mainnet)
/// * `on_payment` callback that is called after bitcoin transfer succeeds
///                until it succeeds
pub async fn execute_payment<B: BitcoinCoreApi, F, R>(
    btc_rpc: Arc<B>,
    num_confirmations: u32,
    btc_address: H160,
    amount_polka_btc: u128,
    event_id: H256,
    network: bitcoin::Network,
    on_payment: F,
) -> Result<(), Error>
where
    F: Fn(H256Le, u32, Vec<u8>, Vec<u8>) -> R,
    R: Future<Output = Result<(), Error>>,
{
    let address = bitcoin::hash_to_p2wpkh(btc_address, network)
        .map_err(|e| -> bitcoin::Error { e.into() })?;

    info!("Sending bitcoin to {}", btc_address);

    // Step 1: make bitcoin transfer. Note: do not retry this call;
    // the call could fail to get the metadata even if the transaction
    // itself was successful
    let tx_metadata = btc_rpc
        .send_to_address(
            address.clone(),
            amount_polka_btc as u64,
            &event_id.to_fixed_bytes(),
            MAX_RETRYING_TIME,
            num_confirmations,
        )
        .await?;

    info!("Bitcoin successfully sent to {}", btc_address);

    // step 2: try callback until it succeeds or times out
    // For now, this is either execute_redeem or execute_replace
    (|| async {
        Ok(on_payment(
            H256Le::from_bytes_le(tx_metadata.txid.as_ref()),
            tx_metadata.block_height,
            tx_metadata.proof.clone(),
            tx_metadata.raw_tx.clone(),
        )
        .await?)
    })
    .retry(get_retry_policy())
    .await?;

    Ok(())
}

/// gets our default retrying policy
pub fn get_retry_policy() -> ExponentialBackoff {
    ExponentialBackoff {
        max_elapsed_time: Some(MAX_RETRYING_TIME),
        ..Default::default()
    }
}

pub async fn check_every<'a, F>(duration: Duration, check: impl Fn() -> F)
where
    F: Future<Output = Result<(), Error>> + 'a,
{
    loop {
        if let Err(e) = check().await {
            error!("Error: {}", e.to_string())
        }
        delay_for(duration).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        BlockHash, Error as BitcoinError, GetRawTransactionResult, TransactionMetadata, Txid, Network
    };

    macro_rules! assert_ok {
        ( $x:expr $(,)? ) => {
            let is = $x;
            match is {
                Ok(_) => (),
                _ => assert!(false, "Expected Ok(_). Got {:#?}", is),
            }
        };
        ( $x:expr, $y:expr $(,)? ) => {
            assert_eq!($x, Ok($y));
        };
    }

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait BitcoinCoreApi {
            async fn wait_for_block(&self, height: u32, delay: Duration) -> Result<BlockHash, BitcoinError>;
            fn get_block_count(&self) -> Result<u64, BitcoinError>;
            fn get_block_transactions(
                &self,
                hash: &BlockHash,
            ) -> Result<Vec<Option<GetRawTransactionResult>>, BitcoinError>;
            fn get_raw_tx_for(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            fn get_proof_for(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            fn get_block_hash_for(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            fn is_block_known(&self, block_hash: BlockHash) -> Result<bool, BitcoinError>;
            fn get_new_address(&self) -> Result<H160, BitcoinError>;
            async fn send_to_address(
                &self,
                address: String,
                sat: u64,
                redeem_id: &[u8; 32],
                op_timeout: Duration,
                num_confirmations: u32,
            ) -> Result<TransactionMetadata, BitcoinError>;
        }
    }

    fn dummy_transaction_metadata() -> TransactionMetadata {
        TransactionMetadata {
            block_hash: Default::default(),
            block_height: Default::default(),
            proof: Default::default(),
            raw_tx: Default::default(),
            txid: Default::default(),
        }
    }
    #[tokio::test]
    async fn test_execute_payment_succeeds() {
        let mut provider = MockProvider::default();
        provider
            .expect_send_to_address()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Ok(dummy_transaction_metadata()));

        let on_payment_called = std::cell::Cell::new(false);
        let on_payment = |_, _, _, _| async {
            on_payment_called.set(true);
            Ok(())
        };
        assert_ok!(
            execute_payment(
                Arc::new(provider),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Network::Regtest,
                on_payment,
            )
            .await
        );
        // Check that the callback was called
        assert!(on_payment_called.get());
    }

    #[tokio::test]
    async fn test_execute_payment_no_bitcoin_retry() {
        let mut provider = MockProvider::default();
        provider
            .expect_send_to_address()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Err(BitcoinError::ConfirmationError));

        let on_payment_called = std::cell::Cell::new(false);
        let on_payment = |_, _, _, _| async {
            on_payment_called.set(true);
            Ok(())
        };
        assert_err!(
            execute_payment(
                Arc::new(provider),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Network::Regtest,
                on_payment,
            )
            .await,
            Error::BitcoinError(BitcoinError::ConfirmationError)
        );
        // Check that the callback was not called
        assert!(!on_payment_called.get());
    }

    #[tokio::test]
    async fn test_execute_payment_callback_retry() {
        let mut provider = MockProvider::default();
        provider
            .expect_send_to_address()
            .times(1) // checks that this function is not retried
            .returning(|_, _, _, _, _| Ok(dummy_transaction_metadata()));

        let callback_count = std::cell::Cell::new(0u32);
        let on_payment = |_, _, _, _| async {
            callback_count.set(callback_count.get() + 1);
            if callback_count.get() == 2 {
                Ok(())
            } else {
                Err(Error::InsufficientFunds)
            }
        };
        assert_ok!(
            execute_payment(
                Arc::new(provider),
                Default::default(),
                Default::default(),
                Default::default(),
                Default::default(),
                Network::Regtest,
                on_payment,
            )
            .await,
        );

        // Check that the callback was called exactly twice
        assert!(callback_count.get() == 2);
    }
}
