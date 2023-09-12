#![cfg(feature = "uses-bitcoind")]

use bitcoin::{
    Amount, Auth, BitcoinCore, BitcoinCoreApi, BitcoinCoreBuilder, Error, Network, PrivateKey, PublicKey, RpcApi,
};
use bitcoincore_rpc::json;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use std::env::var;

fn new_bitcoin_core(wallet: Option<String>) -> Result<BitcoinCore, Error> {
    BitcoinCoreBuilder::new(var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL not set"))
        .set_auth(Auth::UserPass(
            var("BITCOIN_RPC_USER").expect("BITCOIN_RPC_USER not set"),
            var("BITCOIN_RPC_PASS").expect("BITCOIN_RPC_PASS not set"),
        ))
        .set_wallet_name(wallet)
        .build_with_network(Network::Regtest)
}

#[tokio::test]
async fn should_get_new_address() -> Result<(), Error> {
    let btc_rpc = new_bitcoin_core(Some("Alice".to_string()))?;
    btc_rpc.create_or_load_wallet().await?;

    let re = Regex::new("^(bcrt1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$").unwrap();
    let address = btc_rpc.get_new_address().await?;
    assert!(re.is_match(&address.to_string()));

    Ok(())
}

#[tokio::test]
async fn should_list_addresses() -> Result<(), Error> {
    let btc_rpc = new_bitcoin_core(Some("Alice".to_string()))?;
    btc_rpc.create_or_load_wallet().await?;

    let address = btc_rpc.get_new_address().await?;
    btc_rpc.mine_blocks(101, Some(address.clone()));

    assert!(
        btc_rpc.list_addresses()?.contains(&address),
        "Address not found in groupings"
    );

    Ok(())
}

#[tokio::test]
async fn should_get_new_public_key() -> Result<(), Error> {
    let btc_rpc = new_bitcoin_core(Some("Bob".to_string()))?;
    btc_rpc.create_or_load_wallet().await?;

    let public_key = btc_rpc.get_new_public_key().await?;
    assert!(btc_rpc.wallet_has_public_key(public_key).await?);

    Ok(())
}

#[tokio::test]
async fn should_add_new_deposit_key() -> Result<(), Error> {
    let btc_rpc = new_bitcoin_core(Some("Charlie".to_string()))?;
    btc_rpc.create_or_load_wallet().await?;

    btc_rpc
        .import_private_key(PrivateKey::from_wif(
            "cNfmpdkMyUwQGEZgqiqu1RPhhrjwGsp5VSJhEnFEfU533KwTnuYj",
        )?)
        .await?;

    // bcrt1qzrkyemjkaxq48zwlnhxvear8fh6lvkwszxy7dm
    let old_public_key = PublicKey::from_slice(&vec![
        2, 123, 236, 243, 192, 100, 34, 40, 51, 111, 129, 130, 160, 64, 129, 135, 11, 184, 68, 84, 83, 198, 234, 196,
        150, 13, 208, 86, 34, 150, 10, 59, 247,
    ])
    .unwrap();

    let secret_key = vec![
        137, 16, 46, 159, 212, 158, 232, 178, 197, 253, 105, 137, 102, 159, 70, 217, 110, 211, 254, 82, 216, 4, 105,
        171, 102, 252, 54, 190, 114, 91, 11, 69,
    ];

    btc_rpc.add_new_deposit_key(old_public_key, secret_key).await?;

    // bcrt1qn9mgwncjtnavx23utveqqcrxh3zjtll58pc744
    let new_public_key = PublicKey::from_slice(&vec![
        2, 151, 202, 113, 10, 9, 43, 125, 187, 101, 157, 152, 191, 94, 12, 236, 133, 229, 16, 233, 221, 52, 150, 183,
        243, 61, 110, 8, 152, 132, 99, 49, 189,
    ])
    .unwrap();

    assert!(btc_rpc.wallet_has_public_key(new_public_key).await?);

    Ok(())
}

fn rand_wallet_name() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect()
}

#[tokio::test]
async fn should_sweep_funds() -> Result<(), Error> {
    let btc_rpc1 = new_bitcoin_core(Some(rand_wallet_name()))?;
    btc_rpc1.create_or_load_wallet().await?;

    let btc_rpc2 = new_bitcoin_core(Some(rand_wallet_name()))?;
    btc_rpc2.create_or_load_wallet().await?;

    let btc_rpc3 = new_bitcoin_core(Some(rand_wallet_name()))?;
    btc_rpc3.create_or_load_wallet().await?;

    // blocks must have 100 confirmations for reward to be spent
    let address1 = btc_rpc1.get_new_address().await?;
    btc_rpc1.mine_blocks(101, Some(address1));

    let address2 = btc_rpc2.get_new_address().await?;
    let txid = btc_rpc1.rpc.send_to_address(
        &address2,
        Amount::from_sat(100000),
        None,
        None,
        None,
        None,
        None,
        Some(json::EstimateMode::Economical),
    )?;
    btc_rpc1.mine_blocks(1, None);

    assert_eq!(btc_rpc2.get_balance(None)?.to_sat(), 100000);

    let address3 = btc_rpc3.get_new_address().await?;
    let _txid = btc_rpc2.sweep_funds(address3).await?;
    btc_rpc1.mine_blocks(1, None);

    assert_eq!(btc_rpc2.get_balance(None)?.to_sat(), 0);
    // balance before minus fees
    assert_eq!(btc_rpc3.get_balance(None)?.to_sat(), 97800);

    Ok(())
}
