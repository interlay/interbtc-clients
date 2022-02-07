#![cfg(feature = "uses-bitcoind")]

use bitcoin::{
    Auth, BitcoinCore, BitcoinCoreApi, BitcoinCoreBuilder, Error, Network, PartialAddress, Payload, PrivateKey,
    PUBLIC_KEY_SIZE,
};
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
    let address: Payload = btc_rpc.get_new_address().await?;
    assert!(re.is_match(&address.encode_str(Network::Regtest)?));

    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct TestPublicKey([u8; PUBLIC_KEY_SIZE]);

impl From<[u8; PUBLIC_KEY_SIZE]> for TestPublicKey {
    fn from(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl Into<[u8; PUBLIC_KEY_SIZE]> for TestPublicKey {
    fn into(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0
    }
}

#[tokio::test]
async fn should_get_new_public_key() -> Result<(), Error> {
    let btc_rpc = new_bitcoin_core(Some("Bob".to_string()))?;
    btc_rpc.create_or_load_wallet().await?;

    let public_key: TestPublicKey = btc_rpc.get_new_public_key().await?;
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
    let old_public_key = TestPublicKey([
        2, 123, 236, 243, 192, 100, 34, 40, 51, 111, 129, 130, 160, 64, 129, 135, 11, 184, 68, 84, 83, 198, 234, 196,
        150, 13, 208, 86, 34, 150, 10, 59, 247,
    ]);

    let secret_key = vec![
        137, 16, 46, 159, 212, 158, 232, 178, 197, 253, 105, 137, 102, 159, 70, 217, 110, 211, 254, 82, 216, 4, 105,
        171, 102, 252, 54, 190, 114, 91, 11, 69,
    ];

    btc_rpc.add_new_deposit_key(old_public_key, secret_key).await?;

    // bcrt1qn9mgwncjtnavx23utveqqcrxh3zjtll58pc744
    let new_public_key = TestPublicKey([
        2, 151, 202, 113, 10, 9, 43, 125, 187, 101, 157, 152, 191, 94, 12, 236, 133, 229, 16, 233, 221, 52, 150, 183,
        243, 61, 110, 8, 152, 132, 99, 49, 189,
    ]);

    assert!(btc_rpc.wallet_has_public_key(new_public_key).await?);

    Ok(())
}
