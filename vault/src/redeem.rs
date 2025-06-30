use crate::{
    execution::*,
    metrics::{publish_expected_bitcoin_balance, PerCurrencyMetrics},
    service::{spawn_cancelable, ShutdownSender},
    system::{VaultData, VaultIdManager},
    Error,
};
use runtime::{
    AccountId, ForeignAsset, InterBtcParachain, RedeemPallet, RequestRedeemEvent, Token, VaultId, DOT, H256, IBTC,
    KBTC, KSM,
};
use std::{str::FromStr, time::Duration};

/// Listen for RequestRedeemEvent directed at this vault; upon reception, transfer
/// bitcoin and call execute_redeem
///
/// # Arguments
///
/// * `parachain_rpc` - the parachain RPC handle
/// * `btc_rpc` - the bitcoin RPC handle
/// * `network` - network the bitcoin network used (i.e. regtest/testnet/mainnet)
/// * `num_confirmations` - the number of bitcoin confirmation to await
pub async fn listen_for_redeem_requests(
    shutdown_tx: ShutdownSender,
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager,
    num_confirmations: u32,
    payment_margin: Duration,
    auto_rbf: bool,
) -> Result<(), Error> {
    println!("Executing particular redeem request");

    // update redeem id, vault id and btc txid
    let redeem_id = H256::from_str("0xab6810beb213f6c0e87032acdfa51887ba20166099e4d0d65d2ecbe5433b725b").unwrap();
    println!("redeem_id: {}", redeem_id);

    let request = Request::from_redeem_request(
        redeem_id,
        parachain_rpc.get_redeem_request(redeem_id).await?,
        payment_margin,
    )?;

    let vault_id = VaultId::new(
        AccountId::from_str("wdAMp3A8rznqnuzmpbBq4Hva9UnJAmUyN3AwHuhECsCDdcWtw").unwrap(),
        ForeignAsset(3),
        Token(IBTC),
    );

    let vault_data = VaultData {
        vault_id,
        btc_rpc: vault_id_manager.btc_rpc_master_wallet,
        metrics: PerCurrencyMetrics::dummy(),
    };

    request
        .pay_and_execute(parachain_rpc, vault_data, num_confirmations, auto_rbf)
        .await
        .unwrap();
    Ok(())
}
