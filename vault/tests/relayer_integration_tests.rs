#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use runtime::integration::*;

use bitcoin::{BitcoinCoreApi, BlockHash, Hash, TransactionExt, Txid};
use frame_support::assert_ok;
use futures::{
    channel::mpsc,
    future::{join, try_join, Either},
    pin_mut, Future, FutureExt, SinkExt, StreamExt,
};
use runtime::{
    pallets::relay::*,
    substrate_subxt::{Event, PairSigner},
    BtcAddress, BtcRelayPallet, CurrencyId, ErrorCode, FeePallet, FixedPointNumber, FixedU128, H256Le,
    InterBtcParachain, InterBtcRuntime, IssuePallet, OraclePallet, RedeemPallet, RelayPallet, ReplacePallet,
    StatusCode, UtilFuncs, VaultRegistryPallet,
};
use sp_core::H160;
use sp_keyring::AccountKeyring;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;
use vault;

const TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_TESTING_CURRENCY: CurrencyId = CurrencyId::DOT;

#[tokio::test(flavor = "multi_thread")]
async fn test_report_vault_theft_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

    set_exchange_rate(&relayer_provider, FixedU128::saturating_from_rational(1u128, 100u128)).await;

    assert_ok!(
        try_join(
            root_provider.set_bitcoin_confirmations(0),
            root_provider.set_parachain_confirmations(0),
        )
        .await
    );

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    let issue_amount = 100000;
    let vault_collateral = get_required_vault_collateral_for_issue(&vault_provider, issue_amount).await;
    assert_ok!(
        vault_provider
            .register_vault(
                vault_collateral,
                btc_rpc.get_new_public_key().await.unwrap(),
                DEFAULT_TESTING_CURRENCY
            )
            .await
    );

    let vaults = Arc::new(vault::Vaults::from(Default::default()));

    test_service(
        join(
            vault::service::report_vault_thefts(btc_rpc.clone(), relayer_provider.clone(), 0, vaults.clone()),
            vault::service::listen_for_wallet_updates(relayer_provider.clone(), vaults.clone()),
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
            assert_ok!(vault_provider.register_address(input_address).await);

            // now perform the theft
            assert_ok!(btc_rpc.send_transaction(transaction).await);

            assert_event::<VaultTheftEvent<InterBtcRuntime>, _>(TIMEOUT, vault_provider, |_| true).await;
        },
    )
    .await
}
