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
use vault::{self, Event as CancellationEvent, IssueRequests, VaultIdManager, ZeroDelay};

#[tokio::test(flavor = "multi_thread")]
async fn test_report_vault_theft_succeeds() {
    service::init_subscriber();

    let (client, _tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
    let root_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
    let vault_provider = setup_provider(client.clone(), AccountKeyring::Charlie).await;
    let vault_id = VaultId::new(
        AccountKeyring::Charlie.into(),
        DEFAULT_TESTING_CURRENCY,
        DEFAULT_WRAPPED_CURRENCY,
    );

    let uri = b"/usr/bin/ls".to_vec();
    let code_hash = H256::default();

    assert_ok!(root_provider.set_current_client_release(uri, code_hash).await);
}
