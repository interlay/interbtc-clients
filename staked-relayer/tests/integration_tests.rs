#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use runtime::integration::*;

use bitcoin::{BitcoinCoreApi, BlockHash, Hash, TransactionExt, Txid};
use futures::{
    channel::mpsc,
    future::{join, try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use runtime::{
    pallets::staked_relayers::*,
    substrate_subxt::{Event, PairSigner},
    BtcAddress, BtcRelayPallet, ErrorCode, ExchangeRateOraclePallet, FeePallet, FixedPointNumber, FixedU128, H256Le,
    IssuePallet, PolkaBtcProvider, PolkaBtcRuntime, RedeemPallet, ReplacePallet, StakedRelayerPallet, StatusCode,
    UtilFuncs, VaultRegistryPallet,
};
use sp_core::H160;
use sp_keyring::AccountKeyring;
use staked_relayer;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(600);

#[tokio::test(threaded_scheduler)]
async fn test_report_vault_theft_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    relayer_provider
        .set_exchange_rate_info(FixedU128::saturating_from_rational(1u128, 100u128))
        .await
        .unwrap();

    try_join(
        root_provider.set_bitcoin_confirmations(0),
        root_provider.set_parachain_confirmations(0),
    )
    .await
    .unwrap();

    relayer_provider.register_staked_relayer(1000000).await.unwrap();

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    vault_provider
        .register_vault(vault_collateral, btc_rpc.get_new_public_key().await.unwrap())
        .await
        .unwrap();

    let vaults = Arc::new(staked_relayer::Vaults::from(Default::default()));

    test_service(
        join(
            staked_relayer::service::report_vault_thefts(
                btc_rpc.clone(),
                relayer_provider.clone(),
                0,
                vaults.clone(),
                Duration::from_secs(1),
            ),
            staked_relayer::service::listen_for_wallet_updates(relayer_provider.clone(), vaults.clone()),
        ),
        async {
            // Theft detection works by extracting the public address from transaction inputs,
            // and comparing them to registered vault addresses.
            // We can't easily create a spending input corresponding to a output address, because
            // the input script does not contain the public key; rather, it contains a hash `x`
            // such that `hash(x)` is equal to the output address.
            // To work around this, we create an arbitrary spending script, and then calculate the
            // corresponding output address. Then, we make the vault register the address and we
            // proceed to spend it.

            // step 1: create a spending transaction from some arbitrary address
            let mut transaction = btc_rpc
                .create_transaction(BtcAddress::P2PKH(H160::from_slice(&[4; 20])), 1500, None)
                .await
                .unwrap();
            // set the hash in the input script. Note: p2wpkh needs to start with 2 or 3
            transaction.transaction.input[0].witness = vec![vec![], vec![3; 33]];

            // extract the public address corresponding to the input script
            let input_address = transaction.transaction.extract_input_addresses::<BtcAddress>()[0];
            // now make the vault register it
            vault_provider.register_address(input_address).await.unwrap();

            // now perform the theft
            btc_rpc.send_transaction(transaction).await.unwrap();

            assert_event::<VaultTheftEvent<PolkaBtcRuntime>, _>(TIMEOUT, vault_provider, |_| true).await;
        },
    )
    .await
}

#[tokio::test(threaded_scheduler)]
async fn test_register_deregister_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;

    relayer_provider.register_staked_relayer(1000000).await.unwrap();

    assert!(relayer_provider.register_staked_relayer(1000000).await.is_err());

    relayer_provider.deregister_staked_relayer().await.unwrap();

    assert!(relayer_provider.deregister_staked_relayer().await.is_err());

    relayer_provider.register_staked_relayer(1000000).await.unwrap();
}
