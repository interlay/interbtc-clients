#![cfg(feature = "standalone-metadata")]

use async_trait::async_trait;
use bitcoin::{stream_blocks, BitcoinCoreApi, TransactionExt};
use frame_support::assert_ok;
use futures::{
    channel::mpsc,
    future::{join, join3, join4, join5, try_join},
    Future, FutureExt, SinkExt, TryStreamExt,
};
use runtime::{
    integration::*, types::*, BtcAddress, CurrencyId, FixedPointNumber, FixedU128, InterBtcParachain,
    InterBtcRedeemRequest, IssuePallet, RedeemPallet, RelayPallet, ReplacePallet, SudoPallet, UtilFuncs, VaultId,
    VaultRegistryPallet,
};
use sp_core::{H160, H256};
use sp_keyring::AccountKeyring;
use std::{sync::Arc, time::Duration};
use vault::{self, Event as CancellationEvent, IssueRequests, OrderedVaultsDelay, VaultIdManager};

const TIMEOUT: Duration = Duration::from_secs(90);

const DEFAULT_NATIVE_CURRENCY: CurrencyId = Token(INTR);
const DEFAULT_TESTING_CURRENCY: CurrencyId = Token(DOT);
const DEFAULT_WRAPPED_CURRENCY: CurrencyId = Token(IBTC);

async fn test_with<F, R>(execute: impl FnOnce(SubxtClient) -> F) -> R
where
    F: Future<Output = R>,
{
    service::init_subscriber();
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Bob).await;

    set_exchange_rate_and_wait(
        &parachain_rpc,
        DEFAULT_TESTING_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;
    set_exchange_rate_and_wait(
        &parachain_rpc,
        DEFAULT_NATIVE_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;
    set_bitcoin_fees(&parachain_rpc, FixedU128::from(0)).await;

    execute(client).await
}

async fn test_with_vault<F, R>(execute: impl FnOnce(SubxtClient, VaultId, InterBtcParachain) -> F) -> R
where
    F: Future<Output = R>,
{
    service::init_subscriber();
    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let parachain_rpc = setup_provider(client.clone(), AccountKeyring::Bob).await;

    set_exchange_rate_and_wait(
        &parachain_rpc,
        DEFAULT_TESTING_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;
    set_exchange_rate_and_wait(
        &parachain_rpc,
        DEFAULT_NATIVE_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;
    set_bitcoin_fees(&parachain_rpc, FixedU128::from(0)).await;

    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault_id = VaultId::new(
        AccountKeyring::Charlie.into(),
        DEFAULT_TESTING_CURRENCY,
        DEFAULT_WRAPPED_CURRENCY,
    );

    execute(client, vault_id, vault_provider).await
}
// seed is to make txid unique for each payment
async fn pay_redeem_from_vault_wallet(
    vault_provider: InterBtcParachain,
    btc_rpc: MockBitcoinCore,
    addr_seed: u8,
    vault_id: VaultId,
) {
    // Theft detection works by extracting the public address from transaction inputs,
    // and comparing them to registered vault addresses.
    // We can't easily create a spending input corresponding to a output address, because
    // the input script does not contain the public key; rather, it contains a hash `x`
    // such that `hash(x)` is equal to the output address.
    // To work around this, we create an arbitrary spending script, and then calculate the
    // corresponding output address. Then, we make the vault register the address and we
    // proceed to spend it.

    let btc_rpc = &btc_rpc;
    let vault_provider = &vault_provider;
    let vault_id = &vault_id;
    vault_provider
        .on_event::<RequestRedeemEvent, _, _, _>(
            |event| async move {
                tracing::error!("Event {}", addr_seed);
                let request = vault_provider.get_redeem_request(event.redeem_id).await.unwrap();
                // step 1: create a spending transaction from some arbitrary address
                let mut transaction = btc_rpc
                    .create_transaction(
                        request.btc_address,
                        request.amount_btc as u64,
                        1000,
                        Some(event.redeem_id),
                    )
                    .await
                    .unwrap();
                let mut x = [3; 33];
                x[1] = addr_seed;
                // set the hash in the input script. Note: p2wpkh needs to start with 2 or 3
                transaction.transaction.input[0].witness = vec![vec![], x.to_vec()];
                // make txid unique
                transaction.transaction.input[0].previous_output.vout = addr_seed as u32;
                // first byte of the script needs to be non-zero in order to be parsed as p2wpkh. If we don't overwrite
                // this, the client will parse the input as p2wpkh, while the parachain parses is as a script hash
                // address
                transaction.transaction.input[0].script_sig = bitcoin::Script::from(vec![
                    1, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234, 210, 186, 21, 187, 98,
                    38, 255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123, 216, 232, 168, 2, 32, 72, 126, 179, 207,
                    142, 8, 99, 8, 32, 78, 244, 166, 106, 160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12,
                    194, 240, 212, 3, 120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247,
                    165, 78, 111, 80, 79, 50, 200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253, 134, 127, 212, 51,
                    33, 2, 128, 200, 184, 235, 148, 25, 43, 34, 28, 173, 55, 54, 189, 164, 187, 243, 243, 152, 7, 84,
                    210, 85, 156, 238, 77, 97, 188, 240, 162, 197, 105, 62, 82, 174,
                ]);

                // extract the public address corresponding to the input script
                let input_address = transaction.transaction.extract_input_addresses::<BtcAddress>()[0];
                tracing::error!("txid {} {}", addr_seed, transaction.transaction.txid());
                // now make the vault register it
                assert_ok!(vault_provider.register_address(vault_id, input_address).await);
                tracing::error!("Registered {}", addr_seed);
                let return_to_self_address = transaction.transaction.extract_output_addresses::<BtcAddress>()[1];
                // register return-to-self address if it hasnt been yet
                let wallet = vault_provider.get_vault(vault_id).await.unwrap().wallet;
                if !wallet.addresses.contains(&return_to_self_address) {
                    vault_provider
                        .register_address(vault_id, return_to_self_address)
                        .await
                        .unwrap();
                }

                // now perform the theft
                assert_ok!(btc_rpc.send_transaction(transaction).await);
                tracing::error!("sent {}", addr_seed);
            },
            |_err| (),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_report_vault_theft_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;

    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault_id = VaultId::new(
        AccountKeyring::Charlie.into(),
        DEFAULT_TESTING_CURRENCY,
        DEFAULT_WRAPPED_CURRENCY,
    );

    set_exchange_rate_and_wait(
        &relayer_provider,
        DEFAULT_TESTING_CURRENCY,
        FixedU128::saturating_from_rational(1u128, 100u128),
    )
    .await;

    assert_ok!(
        try_join(
            root_provider.set_bitcoin_confirmations(0),
            root_provider.set_parachain_confirmations(0),
        )
        .await
    );

    let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

    let issue_amount = 100000;
    let vault_collateral =
        get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency()).await;
    assert_ok!(
        vault_provider
            .register_vault_with_public_key(&vault_id, vault_collateral, btc_rpc.get_new_public_key().await.unwrap(),)
            .await
    );

    let vaults = Arc::new(vault::Vaults::from(Default::default()));
    let random_delay = OrderedVaultsDelay::new(relayer_provider.clone()).await.unwrap();

    test_service(
        join(
            vault::service::monitor_btc_txs(
                btc_rpc.clone(),
                relayer_provider.clone(),
                random_delay.clone(),
                0,
                vaults.clone(),
            ),
            vault::service::listen_for_wallet_updates(relayer_provider.clone(), btc_rpc.network(), vaults.clone()),
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
                .create_transaction(BtcAddress::P2PKH(H160::from_slice(&[4; 20])), 1500, 1000, None)
                .await
                .unwrap();
            // set the hash in the input script. Note: p2wpkh needs to start with 2 or 3
            transaction.transaction.input[0].witness = vec![vec![], vec![3; 33]];
            // first byte of the script needs to be non-zero in order to be parsed as p2wpkh. If we don't overwrite
            // this, the client will parse the input as p2wpkh, while the parachain parses is as a script hash address
            transaction.transaction.input[0].script_sig = bitcoin::Script::from(vec![
                1, 71, 48, 68, 2, 32, 91, 128, 41, 150, 96, 53, 187, 63, 230, 129, 53, 234, 210, 186, 21, 187, 98, 38,
                255, 112, 30, 27, 228, 29, 132, 140, 155, 62, 123, 216, 232, 168, 2, 32, 72, 126, 179, 207, 142, 8, 99,
                8, 32, 78, 244, 166, 106, 160, 207, 227, 61, 210, 172, 234, 234, 93, 59, 159, 79, 12, 194, 240, 212, 3,
                120, 50, 1, 71, 81, 33, 3, 113, 209, 131, 177, 9, 29, 242, 229, 15, 217, 247, 165, 78, 111, 80, 79, 50,
                200, 117, 80, 30, 233, 210, 167, 133, 175, 62, 253, 134, 127, 212, 51, 33, 2, 128, 200, 184, 235, 148,
                25, 43, 34, 28, 173, 55, 54, 189, 164, 187, 243, 243, 152, 7, 84, 210, 85, 156, 238, 77, 97, 188, 240,
                162, 197, 105, 62, 82, 174,
            ]);

            // extract the public address corresponding to the input script
            let input_address = transaction.transaction.extract_input_addresses::<BtcAddress>()[0];
            // now make the vault register it
            assert_ok!(vault_provider.register_address(&vault_id, input_address).await);

            // now perform the theft
            assert_ok!(btc_rpc.send_transaction(transaction).await);

            assert_event::<VaultTheftEvent, _>(TIMEOUT, vault_provider, |_| true).await;
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_report_vault_double_payment_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        // set_exchange_rate(&relayer_provider, FixedU128::saturating_from_rational(1u128, 100u128)).await;

        assert_ok!(
            try_join(
                root_provider.set_bitcoin_confirmations(0),
                root_provider.set_parachain_confirmations(0),
            )
            .await
        );

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );
        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        let vaults = Arc::new(vault::Vaults::from(Default::default()));

        let random_delay = OrderedVaultsDelay::new(relayer_provider.clone()).await.unwrap();

        // we make the vault start two listen_for_redeem_requests processes, this way there will be a double payment
        // that should be reported
        test_service(
            join4(
                vault::service::monitor_btc_txs(
                    btc_rpc.clone(),
                    relayer_provider.clone(),
                    random_delay.clone(),
                    0,
                    vaults.clone(),
                ),
                vault::service::listen_for_wallet_updates(relayer_provider.clone(), btc_rpc.network(), vaults.clone()),
                pay_redeem_from_vault_wallet(vault_provider.clone(), btc_rpc.clone(), 2, vault_id.clone()),
                pay_redeem_from_vault_wallet(vault_provider.clone(), btc_rpc.clone(), 3, vault_id.clone()),
            ),
            async {
                let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
                user_provider
                    .request_redeem(issue_amount / 2, address, &vault_id)
                    .await
                    .unwrap();

                assert_event::<VaultDoublePaymentEvent, _>(Duration::from_secs(120), root_provider, |_| true).await;
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redeem_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);

        test_service(
            vault::service::listen_for_redeem_requests(
                shutdown_tx,
                vault_provider.clone(),
                vault_id_manager,
                0,
                Duration::from_secs(0),
            ),
            async {
                let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
                let redeem_id = user_provider.request_redeem(10000, address, &vault_id).await.unwrap();
                assert_redeem_event(TIMEOUT, user_provider, redeem_id).await;
                // TODO: check bitcoin payment amount
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_replace_succeeds() {
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(new_vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let new_btc_rpc_master_wallet = btc_rpc.clone();
        let _vault_id_manager =
            VaultIdManager::from_map(new_vault_provider.clone(), new_btc_rpc_master_wallet, btc_rpcs);
        let btc_rpcs = vec![
            (old_vault_id.clone(), btc_rpc.clone()),
            (new_vault_id.clone(), btc_rpc.clone()),
        ]
        .into_iter()
        .collect();
        let old_btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager =
            VaultIdManager::from_map(old_vault_provider.clone(), old_btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let (replace_event_tx, _) = mpsc::channel::<CancellationEvent>(16);
        test_service(
            join(
                vault::service::listen_for_replace_requests(
                    new_vault_provider.clone(),
                    vault_id_manager.clone(),
                    replace_event_tx.clone(),
                    true,
                ),
                vault::service::listen_for_accept_replace(
                    shutdown_tx.clone(),
                    old_vault_provider.clone(),
                    vault_id_manager.clone(),
                    0,
                    Duration::from_secs(0),
                ),
            ),
            async {
                old_vault_provider
                    .request_replace(&old_vault_id, issue_amount)
                    .await
                    .unwrap();

                assert_event::<AcceptReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    assert_eq!(e.old_vault_id, old_vault_id);
                    assert_eq!(e.new_vault_id, new_vault_id);
                    true
                })
                .await;
                assert_event::<ExecuteReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                    assert_eq!(e.old_vault_id, old_vault_id);
                    assert_eq!(e.new_vault_id, new_vault_id);
                    true
                })
                .await;
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_maintain_collateral_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        test_service(
            vault::service::maintain_collateralization_rate(vault_provider.clone(), vault_id_manager),
            async {
                // dot per btc increases by 10%
                set_exchange_rate_and_wait(
                    &relayer_provider,
                    DEFAULT_TESTING_CURRENCY,
                    FixedU128::saturating_from_rational(110u128, 10000u128),
                )
                .await;

                assert_event::<DepositCollateralEvent, _>(TIMEOUT, vault_provider.clone(), |e| {
                    assert_eq!(e.new_collateral, vault_collateral / 10);
                    true
                })
                .await;
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_withdraw_replace_succeeds() {
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        join(
            old_vault_provider
                .request_replace(&old_vault_id, issue_amount)
                .map(Result::unwrap),
            assert_event::<RequestReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |_| true),
        )
        .await;

        join(
            old_vault_provider
                .withdraw_replace(&old_vault_id, issue_amount)
                .map(Result::unwrap),
            assert_event::<WithdrawReplaceEvent, _>(TIMEOUT, old_vault_provider.clone(), |e| {
                assert_eq!(e.old_vault_id, old_vault_id);
                true
            }),
        )
        .await;

        let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
        assert!(new_vault_provider
            .accept_replace(&new_vault_id, &old_vault_id, 1u32.into(), vault_collateral, address)
            .await
            .is_err());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_cancellation_succeeds() {
    // tests cancellation of issue, redeem and replace.
    // issue and replace cancellation is tested through the vault's cancellation service.
    // cancel_redeem is called manually
    test_with_vault(|client, old_vault_id, old_vault_provider| async move {
        let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let new_vault_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let new_vault_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(new_vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let new_btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager =
            VaultIdManager::from_map(new_vault_provider.clone(), new_btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &old_vault_provider,
            issue_amount * 10,
            old_vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            old_vault_provider
                .register_vault_with_public_key(
                    &old_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );
        assert_ok!(
            new_vault_provider
                .register_vault_with_public_key(
                    &new_vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &old_vault_id, issue_amount).await;

        // set low timeout periods
        assert_ok!(root_provider.set_issue_period(1).await);
        assert_ok!(root_provider.set_replace_period(1).await);
        assert_ok!(root_provider.set_redeem_period(1).await);

        let (issue_cancellation_event_tx, issue_cancellation_rx) = mpsc::channel::<CancellationEvent>(16);
        let (replace_cancellation_event_tx, replace_cancellation_rx) = mpsc::channel::<CancellationEvent>(16);

        let block_listener = new_vault_provider.clone();
        let issue_set = Arc::new(IssueRequests::new());

        let issue_request_listener = vault::service::listen_for_issue_requests(
            vault_id_manager.clone(),
            new_vault_provider.clone(),
            issue_cancellation_event_tx.clone(),
            issue_set.clone(),
        );

        let issue_cancellation_scheduler = vault::service::CancellationScheduler::new(
            new_vault_provider.clone(),
            new_vault_provider.get_current_chain_height().await.unwrap(),
            0,
            new_vault_provider.get_account_id().clone(),
        );
        let replace_cancellation_scheduler = vault::service::CancellationScheduler::new(
            new_vault_provider.clone(),
            new_vault_provider.get_current_chain_height().await.unwrap(),
            0,
            new_vault_provider.get_account_id().clone(),
        );
        let issue_canceller =
            issue_cancellation_scheduler.handle_cancellation::<vault::service::IssueCanceller>(issue_cancellation_rx);
        let replace_canceller = replace_cancellation_scheduler
            .handle_cancellation::<vault::service::ReplaceCanceller>(replace_cancellation_rx);

        let parachain_block_listener = async {
            let issue_block_tx = &issue_cancellation_event_tx.clone();
            let replace_block_tx = &replace_cancellation_event_tx.clone();

            block_listener
                .clone()
                .on_event::<UpdateActiveBlockEvent, _, _, _>(
                    |event| async move {
                        assert_ok!(
                            issue_block_tx
                                .clone()
                                .send(CancellationEvent::ParachainBlock(event.block_number))
                                .await
                        );
                        assert_ok!(
                            replace_block_tx
                                .clone()
                                .send(CancellationEvent::ParachainBlock(event.block_number))
                                .await
                        );
                    },
                    |_err| (),
                )
                .await
                .unwrap();
        };

        let initial_btc_height = btc_rpc.get_block_count().await.unwrap() as u32;
        let bitcoin_block_listener = async {
            let issue_block_tx = &issue_cancellation_event_tx.clone();
            let replace_block_tx = &replace_cancellation_event_tx.clone();

            stream_blocks(btc_rpc.clone(), initial_btc_height, 1)
                .await
                .try_for_each(|_| async {
                    let height = btc_rpc.get_block_count().await? as u32;
                    let _ = issue_block_tx
                        .clone()
                        .send(CancellationEvent::BitcoinBlock(height))
                        .await;
                    let _ = replace_block_tx
                        .clone()
                        .send(CancellationEvent::BitcoinBlock(height))
                        .await;
                    Ok(())
                })
                .await
                .unwrap();
        };

        test_service(
            join5(
                issue_canceller.map(Result::unwrap),
                replace_canceller.map(Result::unwrap),
                issue_request_listener.map(Result::unwrap),
                parachain_block_listener,
                bitcoin_block_listener,
            ),
            async {
                let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));

                // setup the to-be-cancelled redeem
                let redeem_id = user_provider
                    .request_redeem(20000, address, &old_vault_id)
                    .await
                    .unwrap();

                join3(
                    async {
                        // setup the to-be-cancelled replace
                        assert_ok!(
                            old_vault_provider
                                .request_replace(&old_vault_id, issue_amount / 2)
                                .await
                        );
                        assert_ok!(
                            new_vault_provider
                                .accept_replace(&new_vault_id, &old_vault_id, 10000000u32.into(), 0u32.into(), address)
                                .await
                        );
                        assert_ok!(
                            replace_cancellation_event_tx
                                .clone()
                                .send(CancellationEvent::Opened)
                                .await
                        );

                        // setup the to-be-cancelled issue
                        assert_ok!(user_provider.request_issue(issue_amount, &new_vault_id).await);

                        for _ in 0u32..2 {
                            assert_ok!(
                                btc_rpc
                                    .send_to_address(
                                        BtcAddress::P2PKH(H160::from_slice(&[0; 20])),
                                        100_000,
                                        None,
                                        1000,
                                        1
                                    )
                                    .await
                            );
                        }
                    },
                    assert_event::<CancelIssueEvent, _>(Duration::from_secs(120), user_provider.clone(), |_| true),
                    assert_event::<CancelReplaceEvent, _>(Duration::from_secs(120), user_provider.clone(), |_| true),
                )
                .await;

                // now make sure we can cancel the redeem
                assert_ok!(user_provider.cancel_redeem(redeem_id, true).await);
            },
        )
        .await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_refund_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let sudo_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let refund_service =
            vault::service::listen_for_refund_requests(shutdown_tx, vault_provider.clone(), vault_id_manager, 0, true);

        assert_ok!(sudo_provider.set_parachain_confirmations(0).await);

        let issue_amount = 100000;
        let vault_collateral =
            2 * get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        let fut_user = async {
            let over_payment = 100500;

            let issue = user_provider.request_issue(issue_amount, &vault_id).await.unwrap();

            let metadata = btc_rpc
                .send_to_address(
                    issue.vault_address,
                    (issue.amount + issue.fee) as u64 + over_payment,
                    None,
                    1000,
                    0,
                )
                .await
                .unwrap();

            let (_, refund_request, refund_execution) = join3(
                user_provider.execute_issue(issue.issue_id, &metadata.proof, &metadata.raw_tx),
                // overpayment on execute_issue should emit this event
                assert_event::<RequestRefundEvent, _>(TIMEOUT, user_provider.clone(), |x| x.vault_id == vault_id),
                // the vault should execute the refund request automatically
                assert_event::<ExecuteRefundEvent, _>(2 * TIMEOUT, user_provider.clone(), |_| true),
            )
            .await;

            assert_eq!(refund_request.refund_id, refund_execution.refund_id);
            assert_eq!(refund_execution.amount, (over_payment as f64 / 1.005) as u128);

            // fetch the tx that was used to execute the redeem
            let tx = btc_rpc
                .find_transaction(|tx| tx.get_op_return() == Some(refund_request.refund_id))
                .await
                .unwrap();

            // make the vault register the input used in that transaction
            let input_address = tx.extract_input_addresses::<BtcAddress>()[0];
            assert_ok!(vault_provider.register_address(&vault_id, input_address).await);

            // check that it is not seen as theft
            let metadata = btc_rpc.wait_for_transaction_metadata(tx.txid(), 0).await.unwrap();
            let result = user_provider
                .report_vault_theft(&vault_id, &metadata.proof, &metadata.raw_tx)
                .await;
            assert!(result.unwrap_err().is_valid_refund());
        };

        test_service(refund_service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_issue_overpayment_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        let refund_service =
            vault::service::listen_for_refund_requests(shutdown_tx, vault_provider.clone(), vault_id_manager, 0, true);

        let issue_amount = 100000;
        let over_payment_factor = 3;
        let vault_collateral = get_required_vault_collateral_for_issue(
            &vault_provider,
            issue_amount * over_payment_factor,
            vault_id.collateral_currency(),
        )
        .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        let fut_user = async {
            let issue = user_provider.request_issue(issue_amount, &vault_id).await.unwrap();

            let metadata = btc_rpc
                .send_to_address(
                    issue.vault_address,
                    (issue.amount + issue.fee) as u64 * over_payment_factor as u64,
                    None,
                    1000,
                    0,
                )
                .await
                .unwrap();

            join(
                assert_event::<EndowedEvent, _>(TIMEOUT, user_provider.clone(), |x| {
                    if &x.who == user_provider.get_account_id() {
                        assert_eq!(x.amount, issue.amount * over_payment_factor);
                        true
                    } else {
                        false
                    }
                }),
                user_provider
                    .execute_issue(issue.issue_id, &metadata.proof, &metadata.raw_tx)
                    .map(Result::unwrap),
            )
            .await;
        };

        test_service(refund_service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_automatic_issue_execution_succeeds() {
    test_with_vault(|client, vault1_id, _vault1_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
        let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let vault2_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault2_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault2_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault1_provider, issue_amount, vault1_id.collateral_currency())
                .await;

        assert_ok!(
            vault1_provider
                .register_vault_with_public_key(
                    &vault1_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap()
                )
                .await
        );
        assert_ok!(
            vault2_provider
                .register_vault_with_public_key(
                    &vault2_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap()
                )
                .await
        );

        let fut_user = async {
            let issue = user_provider.request_issue(issue_amount, &vault1_id).await.unwrap();
            tracing::warn!("REQUESTED ISSUE: {:?}", issue);

            assert_ok!(
                btc_rpc
                    .send_to_address(issue.vault_address, (issue.amount + issue.fee) as u64, None, 1000, 0)
                    .await
            );

            // wait for vault2 to execute this issue
            assert_event::<ExecuteIssueEvent, _>(TIMEOUT, user_provider.clone(), move |x| {
                x.vault_id == vault1_id.clone()
            })
            .await;
        };

        let issue_set = Arc::new(IssueRequests::new());
        let random_delay = OrderedVaultsDelay::new(relayer_provider.clone()).await.unwrap();
        let (issue_event_tx, _issue_event_rx) = mpsc::channel::<CancellationEvent>(16);
        let service = join(
            vault::service::listen_for_issue_requests(
                vault_id_manager.clone(),
                vault2_provider.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
            vault::service::process_issue_requests(
                btc_rpc.clone(),
                vault2_provider.clone(),
                issue_set.clone(),
                1,
                0,
                random_delay,
            ),
        );

        test_service(service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
// todo: refactor to reuse code from test_automatic_issue_execution_succeeds
async fn test_automatic_issue_execution_succeeds_with_big_transaction() {
    test_with_vault(|client, vault1_id, _vault1_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let vault1_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
        let vault2_provider = setup_provider(client.clone(), AccountKeyring::Eve).await;
        let vault2_id = VaultId::new(
            AccountKeyring::Eve.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault2_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault2_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault1_provider, issue_amount, vault1_id.collateral_currency())
                .await;
        assert_ok!(
            vault1_provider
                .register_vault_with_public_key(
                    &vault1_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );
        assert_ok!(
            vault2_provider
                .register_vault_with_public_key(
                    &vault2_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        let fut_user = async {
            let issue = user_provider.request_issue(issue_amount, &vault1_id).await.unwrap();
            tracing::warn!("REQUESTED ISSUE: {:?}", issue);

            assert_ok!(
                btc_rpc
                    .send_to_address_with_many_outputs(
                        issue.vault_address,
                        (issue.amount + issue.fee) as u64,
                        None,
                        1000,
                        0
                    )
                    .await
            );

            // wait for vault2 to execute this issue
            assert_event::<ExecuteIssueEvent, _>(TIMEOUT, user_provider.clone(), move |x| x.vault_id == vault1_id)
                .await;
        };

        let issue_set = Arc::new(IssueRequests::new());
        let random_delay = OrderedVaultsDelay::new(relayer_provider.clone()).await.unwrap();
        let (issue_event_tx, _issue_event_rx) = mpsc::channel::<CancellationEvent>(16);
        let service = join(
            vault::service::listen_for_issue_requests(
                vault_id_manager.clone(),
                vault2_provider.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
            vault::service::process_issue_requests(
                btc_rpc.clone(),
                vault2_provider.clone(),
                issue_set.clone(),
                1,
                0,
                random_delay,
            ),
        );

        test_service(service, fut_user).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_execute_open_requests_succeeds() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;
        let btc_rpcs = vec![(vault_id.clone(), btc_rpc.clone())].into_iter().collect();
        let btc_rpc_master_wallet = btc_rpc.clone();
        let vault_id_manager = VaultIdManager::from_map(vault_provider.clone(), btc_rpc_master_wallet, btc_rpcs);

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        let address = BtcAddress::P2PKH(H160::from_slice(&[2; 20]));
        // place replace requests
        let redeem_ids =
            futures::future::join_all((0..3u128).map(|_| user_provider.request_redeem(10000, address, &vault_id)))
                .await
                .into_iter()
                .map(|x| x.unwrap())
                .collect::<Vec<_>>();

        let redeems: Vec<InterBtcRedeemRequest> =
            futures::future::join_all(redeem_ids.iter().map(|id| user_provider.get_redeem_request(*id)))
                .await
                .into_iter()
                .map(|x| x.unwrap())
                .collect::<Vec<_>>();

        // send btc for redeem 0
        assert_ok!(
            btc_rpc
                .send_to_address(address, redeems[0].amount_btc as u64, Some(redeem_ids[0]), 1000, 0)
                .await
        );

        let transaction = btc_rpc
            .create_transaction(address, redeems[1].amount_btc as u64, 1000, Some(redeem_ids[1]))
            .await
            .unwrap()
            .transaction;
        btc_rpc.send_to_mempool(transaction).await;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(16);
        join3(
            vault::service::execute_open_requests(
                shutdown_tx.clone(),
                vault_provider,
                vault_id_manager,
                btc_rpc.clone(),
                0,
                Duration::from_secs(0),
                true,
            )
            .map(Result::unwrap),
            assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[0]),
            assert_redeem_event(TIMEOUT, user_provider.clone(), redeem_ids[2]),
        )
        .await;

        // now move from mempool into chain and await the remaining redeem
        btc_rpc.flush_mempool().await;
        assert_redeem_event(TIMEOUT, user_provider, redeem_ids[1]).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_off_chain_liquidation() {
    test_with_vault(|client, vault_id, vault_provider| async move {
        let relayer_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;

        let btc_rpc = MockBitcoinCore::new(relayer_provider.clone()).await;

        let issue_amount = 100000;
        let vault_collateral =
            get_required_vault_collateral_for_issue(&vault_provider, issue_amount, vault_id.collateral_currency())
                .await;
        assert_ok!(
            vault_provider
                .register_vault_with_public_key(
                    &vault_id,
                    vault_collateral,
                    btc_rpc.get_new_public_key().await.unwrap(),
                )
                .await
        );

        assert_issue(&user_provider, &btc_rpc, &vault_id, issue_amount).await;

        set_exchange_rate_and_wait(&relayer_provider, DEFAULT_TESTING_CURRENCY, FixedU128::from(10)).await;

        assert_event::<LiquidateVaultEvent, _>(TIMEOUT, vault_provider.clone(), |_| true).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_shutdown() {
    test_with(|client| async move {
        let sudo_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let user_provider = setup_provider(client.clone(), AccountKeyring::Dave).await;
        let sudo_vault_id = VaultId::new(
            AccountKeyring::Alice.into(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );

        // register a vault..
        let btc_rpc = MockBitcoinCore::new(sudo_provider.clone()).await;
        assert_ok!(
            sudo_provider
                .register_vault_with_public_key(&sudo_vault_id, 1000000, btc_rpc.get_new_public_key().await.unwrap(),)
                .await
        );

        // shutdown chain..
        assert_ok!(
            sudo_provider
                .sudo(EncodedCall::Security(SecurityCall::set_parachain_status {
                    status_code: StatusCode::Shutdown,
                }))
                .await
        );

        // request issue should fail:
        assert!(user_provider
            .request_issue(10000, &sudo_vault_id)
            .await
            .unwrap_err()
            .is_parachain_shutdown_error());

        // restore parachain status and check that we can issue now
        assert_ok!(
            sudo_provider
                .sudo(EncodedCall::Security(SecurityCall::set_parachain_status {
                    status_code: StatusCode::Running,
                }))
                .await
        );
        assert_ok!(user_provider.request_issue(10000, &sudo_vault_id).await);
    })
    .await;
}

async fn assert_redeem_event(
    duration: Duration,
    parachain_rpc: InterBtcParachain,
    redeem_id: H256,
) -> ExecuteRedeemEvent {
    assert_event::<ExecuteRedeemEvent, _>(duration, parachain_rpc, |x| x.redeem_id == redeem_id).await
}

#[async_trait]
trait InterBtcParachainExt {
    async fn register_vault_with_public_key(
        &self,
        vault_id: &VaultId,
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), runtime::Error>;
}

#[async_trait]
impl InterBtcParachainExt for InterBtcParachain {
    async fn register_vault_with_public_key(
        &self,
        vault_id: &VaultId,
        collateral: u128,
        public_key: BtcPublicKey,
    ) -> Result<(), runtime::Error> {
        self.register_public_key(public_key).await.unwrap();
        self.register_vault(vault_id, collateral).await.unwrap();
        Ok(())
    }
}
