#![cfg(feature = "uses-bitcoind")]

use bitcoin::{
    secp256k1::{constants::SECRET_KEY_SIZE, Secp256k1},
    Address, AddressType, Amount, Auth, BitcoinCoreApi, BitcoinLight, BlockHash, Client, ElectrsClient, Error, Hash,
    Network, PrivateKey, PublicKey, RpcApi, SatPerVbyte, SecretKey, H256,
};
use futures::{future::join, Future};
use rand::{thread_rng, Rng};
use serial_test::serial;
use std::{env::var, time::Duration};
use tokio::time::{sleep, timeout};

const DEFAULT_NETWORK: Network = Network::Regtest;

fn new_random_key_pair() -> (PrivateKey, PublicKey) {
    // NOTE: private key wif cannot encode regtest
    let raw_secret_key: [u8; SECRET_KEY_SIZE] = thread_rng().gen();
    let secret_key = SecretKey::from_slice(&raw_secret_key).unwrap();
    let private_key = PrivateKey::new(secret_key, DEFAULT_NETWORK);
    let public_key = PublicKey::from_private_key(&Secp256k1::new(), &private_key);
    (private_key, public_key)
}

fn new_bitcoin_client() -> Client {
    Client::new(
        &var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL not set"),
        Auth::UserPass(
            var("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER not set"),
            var("BITCOIN_RPC_PASS").expect("BITCOIN_RPC_PASS not set"),
        ),
    )
    .unwrap()
}

fn new_bitcoin_light() -> BitcoinLight {
    BitcoinLight::new(
        Some(var("ELECTRS_URL").expect("ELECTRS_URL not set")),
        new_random_key_pair().0,
    )
    .unwrap()
}

fn new_electrs() -> ElectrsClient {
    ElectrsClient::new(Some(var("ELECTRS_URL").expect("ELECTRS_URL not set")), DEFAULT_NETWORK).unwrap()
}

async fn wait_for_success<F, R, T, E>(f: F) -> T
where
    F: Fn() -> R,
    R: Future<Output = Result<T, E>>,
{
    timeout(Duration::from_secs(20), async move {
        loop {
            match f().await {
                Ok(x) => return x,
                Err(_) => sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .expect("Time limit elapsed")
}

fn mine_blocks(block_num: u64, maybe_address: Option<Address>) -> BlockHash {
    let bitcoin_client = new_bitcoin_client();
    let address = maybe_address.unwrap_or_else(|| {
        bitcoin_client
            .get_new_address(None, Some(AddressType::Bech32))
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap()
    });
    bitcoin_client
        .generate_to_address(block_num, &address)
        .unwrap()
        .last()
        .unwrap()
        .clone()
}

async fn fund_wallet(bitcoin_light: &BitcoinLight) -> Result<(), Error> {
    // need at least 100 confirmations otherwise we get
    // this error: bad-txns-premature-spend-of-coinbase
    let public_key = new_random_key_pair().1;
    let address = Address::p2wpkh(&public_key, DEFAULT_NETWORK).unwrap();
    mine_blocks(101, Some(address));

    // fund the master key
    let master_public_key = bitcoin_light.get_new_public_key().await?;
    let master_address = Address::p2wpkh(&master_public_key, DEFAULT_NETWORK).unwrap();
    // electrs may still include unconfirmed coinbase txs so to
    // avoid this we mine and then send it to the master address
    new_bitcoin_client().send_to_address(
        &master_address,
        Amount::from_sat(100000),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    mine_blocks(1, None);

    // wait for electrs to pickup utxo
    wait_for_success(|| async {
        new_electrs()
            .get_utxos_for_address(&master_address)
            .await
            .map_err(|_| ())?
            .len()
            .gt(&0)
            .then_some(())
            .ok_or(())
    })
    .await;
    Ok(())
}

#[tokio::test]
#[serial]
async fn should_create_transactions() -> Result<(), Error> {
    let bitcoin_light = new_bitcoin_light();
    fund_wallet(&bitcoin_light).await?;

    let address1 = Address::p2wpkh(&new_random_key_pair().1, DEFAULT_NETWORK).unwrap();
    let address2 = Address::p2wpkh(&new_random_key_pair().1, DEFAULT_NETWORK).unwrap();
    let (res1, res2) = join(
        bitcoin_light.create_and_send_transaction(
            address1.clone(),
            1000,
            SatPerVbyte(1),
            Some(H256::from_slice(&[1; 32])),
        ),
        bitcoin_light.create_and_send_transaction(
            address2.clone(),
            1000,
            SatPerVbyte(1),
            Some(H256::from_slice(&[2; 32])),
        ),
    )
    .await;

    let txid1 = res1?;
    let txid2 = res2?;

    let mempool_txs: Vec<_> = bitcoin_light.get_mempool_transactions().await?.collect();
    assert_eq!(mempool_txs.len(), 2);
    assert!(bitcoin_light.is_in_mempool(txid1).await?, "Txid1 not in mempool");
    assert!(bitcoin_light.is_in_mempool(txid2).await?, "Txid2 not in mempool");

    // mine a block to include our transactions
    let block_hash = mine_blocks(1, None);
    // wait for electrs to pickup block
    wait_for_success(|| async { bitcoin_light.get_block(&block_hash).await }).await;

    assert!(
        bitcoin_light.get_proof(txid1, &BlockHash::all_zeros()).await.is_ok(),
        "Txid1 not confirmed"
    );
    assert!(
        bitcoin_light.get_proof(txid2, &BlockHash::all_zeros()).await.is_ok(),
        "Txid2 not confirmed"
    );

    assert!(bitcoin_light
        .get_tx_for_op_return(address1, 1000, H256::from_slice(&[1; 32]))
        .await?
        .is_some());

    assert!(bitcoin_light
        .get_tx_for_op_return(address2, 1000, H256::from_slice(&[2; 32]))
        .await?
        .is_some());

    Ok(())
}

#[tokio::test]
#[serial]
async fn should_bump_fee() -> Result<(), Error> {
    let bitcoin_light = new_bitcoin_light();
    fund_wallet(&bitcoin_light).await?;

    let address = Address::p2wpkh(&new_random_key_pair().1, DEFAULT_NETWORK).unwrap();
    let txid1 = bitcoin_light
        .create_and_send_transaction(address.clone(), 1000, SatPerVbyte(1), Some(H256::from_slice(&[1; 32])))
        .await?;
    assert_eq!(SatPerVbyte(1), bitcoin_light.fee_rate(txid1).await?);

    let txid2 = bitcoin_light.bump_fee(&txid1, address, SatPerVbyte(2)).await?;
    assert_eq!(SatPerVbyte(2), bitcoin_light.fee_rate(txid2).await?);

    let block_hash = mine_blocks(1, None);
    wait_for_success(|| async { new_electrs().get_block_header(&block_hash).await }).await;

    assert!(
        bitcoin_light.get_proof(txid1, &BlockHash::all_zeros()).await.is_err(),
        "Txid1 should not exist"
    );
    assert!(
        bitcoin_light.get_proof(txid2, &BlockHash::all_zeros()).await.is_ok(),
        "Txid2 should be confirmed"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn should_page_address_history() -> Result<(), Error> {
    let public_key = new_random_key_pair().1;
    let address = Address::p2wpkh(&public_key, DEFAULT_NETWORK).unwrap();
    let block_hash = mine_blocks(100, Some(address.clone()));
    wait_for_success(|| async { new_electrs().get_block_header(&block_hash).await }).await;

    let txs = new_electrs().get_address_tx_history_full(&address.to_string()).await?;
    assert!(txs.len().eq(&100));

    Ok(())
}
