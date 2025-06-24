use std::str::FromStr;
use crate::{
    execution::*,
    metrics::publish_expected_bitcoin_balance,
    service::{spawn_cancelable, ShutdownSender},
    system::VaultIdManager,
    Error,
};
use runtime::{AccountId, InterBtcParachain, RedeemPallet, RequestRedeemEvent, Token, VaultId, H256, KBTC, KSM};
use std::time::Duration;
use crate::metrics::PerCurrencyMetrics;
use crate::system::VaultData;

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
    println!("Executing particulae redeem request");
    let redeem_id = H256::from_str("0xb84d675d13d082d5d404ab645f176034b57e1e3f21b2f3a52ee7b1ba6561ccf9").unwrap();
    println!("redeem_id: {}",redeem_id);

    let request = Request::from_redeem_request(
        redeem_id,
        parachain_rpc.get_redeem_request(redeem_id).await?,
        payment_margin,
    )?;

    let vault_id = VaultId::new(
        AccountId::from_str("a3eFe9M2HbAgrQrShEDH2CEvXACtzLhSf4JGkwuT9SQ1EV4ti").unwrap(),
        Token(KSM),
        Token(KBTC)
    );

    let vault_data = VaultData{
        vault_id: vault_id,
        btc_rpc: vault_id_manager.btc_rpc_master_wallet,
        metrics: PerCurrencyMetrics::dummy(),
    };

    request
        .pay_and_execute(parachain_rpc, vault_data, num_confirmations, auto_rbf)
        .await.unwrap();
    Ok(())
}
