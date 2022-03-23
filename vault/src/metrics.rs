use std::{collections::HashMap, convert::TryInto, sync::Arc};

use crate::system::{VaultData, VaultIdManager};
use bitcoin::{
    json::ListTransactionResult, BitcoinCoreApi, GetTransactionResultDetailCategory, SignedAmount, TransactionExt,
};
use futures::{try_join, StreamExt};
use lazy_static::lazy_static;
use runtime::{
    prometheus::{
        gather, proto::MetricFamily, Encoder, Gauge, GaugeVec, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
    },
    CollateralBalancesPallet, CurrencyId, CurrencyIdExt, CurrencyInfo, Error, FeedValuesEvent, FixedU128,
    InterBtcParachain, IssuePallet, IssueRequestStatus, OracleKey, RedeemPallet, RedeemRequestStatus, RefundPallet,
    ReplacePallet, UtilFuncs, VaultId, VaultRegistryPallet,
};
use service::{
    warp::{Rejection, Reply},
    Error as ServiceError,
};
use std::time::Duration;
use tokio::{sync::RwLock, time::sleep};
const SLEEP_DURATION: Duration = Duration::from_secs(5 * 60);

const CURRENCY_LABEL: &str = "currency";
const BTC_BALANCE_TYPE_LABEL: &str = "type";
const REQUEST_STATUS_LABEL: &str = "status";

// Metrics are stored under the [`CURRENCY_LABEL`] key so that multiple vaults can be easily
// monitored at the same time.
lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref AVERAGE_BTC_FEE: GaugeVec =
        GaugeVec::new(Opts::new("avg_btc_fee", "Average Bitcoin Fee"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref LOCKED_COLLATERAL: GaugeVec =
        GaugeVec::new(Opts::new("locked_collateral", "Locked Collateral"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref COLLATERALIZATION: GaugeVec =
        GaugeVec::new(Opts::new("collateralization", "Collateralization"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
    pub static ref REQUIRED_COLLATERAL: GaugeVec = GaugeVec::new(
        Opts::new("required_collateral", "Required Collateral"),
        &[CURRENCY_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref UTXO_COUNT: IntGaugeVec = IntGaugeVec::new(
        Opts::new("utxo_count", "Number of Unspent Bitcoin Outputs"),
        &[CURRENCY_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref BTC_BALANCE: GaugeVec = GaugeVec::new(
        Opts::new("btc_balance", "Bitcoin Balance"),
        &[CURRENCY_LABEL, BTC_BALANCE_TYPE_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref ISSUES: GaugeVec = GaugeVec::new(
        Opts::new("issue_count", "Number of issues"),
        &[CURRENCY_LABEL, REQUEST_STATUS_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref REDEEMS: GaugeVec = GaugeVec::new(
        Opts::new("redeem_count", "Number of redeems"),
        &[CURRENCY_LABEL, REQUEST_STATUS_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref NATIVE_CURRENCY_BALANCE: Gauge =
        Gauge::new("native_currency_balance", "Native Currency Balance").expect("Failed to create prometheus metric");
    pub static ref FEE_BUDGET_SURPLUS: GaugeVec =
        GaugeVec::new(Opts::new("fee_budget_surplus", "Fee Budget Surplus"), &[CURRENCY_LABEL])
            .expect("Failed to create prometheus metric");
}

#[derive(Clone, Debug)]
struct AverageTracker {
    total: u64,
    count: u64,
}

#[derive(Clone, Debug)]
struct StatefulGauge<T: Clone> {
    gauge: Gauge,
    data: Arc<RwLock<T>>,
}

#[derive(Clone, Debug)]
struct BtcBalance {
    upperbound: Gauge,
    lowerbound: Gauge,
    actual: Gauge,
}

#[derive(Clone, Debug)]
struct RequestCounter {
    open_count: Gauge,
    completed_count: Gauge,
    expired_count: Gauge,
}

#[derive(Clone, Debug)]
pub struct PerCurrencyMetrics {
    locked_collateral: Gauge,
    collateralization: Gauge,
    required_collateral: Gauge,
    btc_balance: BtcBalance,
    issues: RequestCounter,
    redeems: RequestCounter,
    average_btc_fee: StatefulGauge<AverageTracker>,
    fee_budget_surplus: StatefulGauge<i64>,
    utxo_count: IntGauge,
}

impl PerCurrencyMetrics {
    pub fn new(vault_id: &VaultId) -> Self {
        let label = format!(
            "{}_{}",
            vault_id.collateral_currency().inner().symbol(),
            vault_id.wrapped_currency().inner().symbol()
        );
        Self::new_with_label(label.as_ref())
    }

    // construct a dummy metrics struct for testing purposes
    pub fn dummy() -> Self {
        Self::new_with_label("dummy")
    }

    fn new_with_label(label: &str) -> Self {
        let labels = HashMap::from([(CURRENCY_LABEL, label.as_ref())]);

        let btc_balance_gauge = |balance_type: &'static str| {
            let labels =
                HashMap::<&str, &str>::from([(CURRENCY_LABEL, label.as_ref()), (BTC_BALANCE_TYPE_LABEL, balance_type)]);
            BTC_BALANCE.with(&labels)
        };
        let request_type_label = |balance_type: &'static str| {
            HashMap::<&str, &str>::from([(CURRENCY_LABEL, label.as_ref()), (REQUEST_STATUS_LABEL, balance_type)])
        };

        Self {
            locked_collateral: LOCKED_COLLATERAL.with(&labels),
            collateralization: COLLATERALIZATION.with(&labels),
            required_collateral: REQUIRED_COLLATERAL.with(&labels),
            utxo_count: UTXO_COUNT.with(&labels),
            fee_budget_surplus: StatefulGauge {
                gauge: FEE_BUDGET_SURPLUS.with(&labels),
                data: Arc::new(RwLock::new(0)),
            },
            average_btc_fee: StatefulGauge {
                gauge: AVERAGE_BTC_FEE.with(&labels),
                data: Arc::new(RwLock::new(AverageTracker { total: 0, count: 0 })),
            },
            btc_balance: BtcBalance {
                upperbound: btc_balance_gauge("required_upperbound"),
                lowerbound: btc_balance_gauge("required_lowerbound"),
                actual: btc_balance_gauge("actual"),
            },
            issues: RequestCounter {
                open_count: ISSUES.with(&request_type_label("open")),
                completed_count: ISSUES.with(&request_type_label("completed")),
                expired_count: ISSUES.with(&request_type_label("expired")),
            },
            redeems: RequestCounter {
                open_count: REDEEMS.with(&request_type_label("open")),
                completed_count: REDEEMS.with(&request_type_label("completed")),
                expired_count: REDEEMS.with(&request_type_label("expired")),
            },
        }
    }
    async fn initialize_fee_budget_surplus<B: BitcoinCoreApi + Clone + Send + Sync>(
        vault: &VaultData<B>,
        parachain_rpc: InterBtcParachain,
        bitcoin_transactions: Vec<ListTransactionResult>,
    ) {
        let vault_id = &vault.vault_id;
        // update fee surplus
        if let Ok((redeem_requests, replace_requests, refund_requests)) = try_join!(
            parachain_rpc.get_vault_redeem_requests(vault_id.account_id.clone()),
            parachain_rpc.get_old_vault_replace_requests(vault_id.account_id.clone()),
            parachain_rpc.get_vault_refund_requests(vault_id.account_id.clone()),
        ) {
            let redeems = redeem_requests
                .iter()
                .map(|(id, redeem)| (id.clone(), redeem.transfer_fee_btc));
            let refunds = refund_requests
                .iter()
                .map(|(id, refund)| (id.clone(), refund.transfer_fee_btc));
            let replaces = replace_requests.iter().map(|(id, _)| (id.clone(), 0));
            let fee_budgets = redeems.chain(refunds).chain(replaces).collect::<HashMap<_, _>>();
            let fee_budgets = &fee_budgets;

            let fee_budget_surplus = futures::stream::iter(bitcoin_transactions.iter())
                .filter_map(|tx| async move {
                    let transaction = vault
                        .btc_rpc
                        .get_transaction(&tx.info.txid, tx.info.blockhash)
                        .await
                        .ok()?;
                    let op_return = transaction.get_op_return()?;
                    let budget: i64 = fee_budgets.get(&op_return)?.clone().try_into().ok()?;
                    let surplus = budget.checked_sub(tx.detail.fee?.as_sat().abs());
                    surplus
                })
                .fold(0i64, |acc, x| async move { acc.saturating_add(x) })
                .await;

            *vault.metrics.fee_budget_surplus.data.write().await = fee_budget_surplus;
            publish_fee_budget_surplus(&vault).await;
        }
    }
    pub async fn initialize_values<B: BitcoinCoreApi + Clone + Send + Sync>(
        parachain_rpc: InterBtcParachain,
        vault: &VaultData<B>,
    ) {
        let bitcoin_transactions = match vault.btc_rpc.list_transactions(None) {
            Ok(x) => x
                .into_iter()
                .filter(|x| x.detail.category == GetTransactionResultDetailCategory::Send)
                .collect(),
            Err(_) => vec![],
        };

        // update average fee
        let (total, count) = bitcoin_transactions
            .iter()
            .filter_map(|tx| tx.detail.fee.map(|amount| amount.as_sat().abs() as u64))
            .fold((0, 0), |(total, count), x| (total + x, count + 1));
        *vault.metrics.average_btc_fee.data.write().await = AverageTracker { total, count };

        publish_utxo_count(vault);
        publish_bitcoin_balance(vault);

        tokio::join!(
            Self::initialize_fee_budget_surplus(vault, parachain_rpc.clone(), bitcoin_transactions),
            publish_average_bitcoin_fee(vault),
            publish_expected_bitcoin_balance(vault, parachain_rpc.clone()),
            publish_locked_collateral(vault, parachain_rpc.clone()),
            publish_required_collateral(vault, parachain_rpc.clone()),
            publish_collateralization(vault, parachain_rpc.clone()),
        );
    }
}

pub fn register_custom_metrics() -> Result<(), Error> {
    REGISTRY.register(Box::new(AVERAGE_BTC_FEE.clone()))?;
    REGISTRY.register(Box::new(LOCKED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(COLLATERALIZATION.clone()))?;
    REGISTRY.register(Box::new(REQUIRED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(FEE_BUDGET_SURPLUS.clone()))?;
    REGISTRY.register(Box::new(BTC_BALANCE.clone()))?;
    REGISTRY.register(Box::new(NATIVE_CURRENCY_BALANCE.clone()))?;
    REGISTRY.register(Box::new(ISSUES.clone()))?;
    REGISTRY.register(Box::new(REDEEMS.clone()))?;
    REGISTRY.register(Box::new(UTXO_COUNT.clone()))?;

    Ok(())
}

fn serialize(metrics: &[MetricFamily]) -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metrics, &mut buffer) {
        eprintln!("could not encode metrics: {}", e);
    };
    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("metrics could not be parsed `from_utf8`: {}", e);
            String::default()
        }
    };
    buffer.clear();
    res
}

pub async fn metrics_handler() -> Result<impl Reply, Rejection> {
    let mut metrics = serialize(&REGISTRY.gather());
    let custom_metrics = serialize(&gather());
    metrics.push_str(&custom_metrics);
    Ok(metrics)
}

fn raw_value_as_currency(value: u128, currency: CurrencyId) -> f64 {
    let scaling_factor = currency.one() as f64;
    value as f64 / scaling_factor
}

pub async fn publish_locked_collateral<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: &VaultData<B>,
    parachain_rpc: InterBtcParachain,
) {
    if let Ok(actual_collateral) = parachain_rpc.get_vault_total_collateral(vault.vault_id.clone()).await {
        let actual_collateral = raw_value_as_currency(actual_collateral, vault.vault_id.collateral_currency());
        vault.metrics.locked_collateral.set(actual_collateral);
    }
}

pub async fn publish_required_collateral<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: &VaultData<B>,
    parachain_rpc: InterBtcParachain,
) {
    if let Ok(required_collateral) = parachain_rpc
        .get_required_collateral_for_vault(vault.vault_id.clone())
        .await
    {
        let required_collateral = raw_value_as_currency(required_collateral, vault.vault_id.collateral_currency());
        vault.metrics.required_collateral.set(required_collateral);
    }
}

pub async fn publish_collateralization<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: &VaultData<B>,
    parachain_rpc: InterBtcParachain,
) {
    // if the collateralization is infinite, return 0 rather than logging an error, so
    // the metrics do change in case of a replacement
    let collateralization = parachain_rpc
        .get_collateralization_from_vault(vault.vault_id.clone(), false)
        .await
        .unwrap_or(0u128);
    let float_collateralization_percentage = FixedU128::from_inner(collateralization).to_float();
    vault.metrics.collateralization.set(float_collateralization_percentage);
}

pub async fn update_bitcoin_metrics<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: VaultData<B>,
    new_fee_entry: Option<SignedAmount>,
    fee_budget: Option<u128>,
) {
    // update the average fee
    if let Some(amount) = new_fee_entry {
        {
            let mut tmp = vault.metrics.average_btc_fee.data.write().await;
            *tmp = AverageTracker {
                total: tmp.total.saturating_add(amount.as_sat().abs() as u64),
                count: tmp.count.saturating_add(1),
            };
        }
        publish_average_bitcoin_fee(&vault).await;

        if let Ok(budget) = TryInto::<i64>::try_into(fee_budget.unwrap_or(0)) {
            let surplus = budget.saturating_sub(amount.as_sat().abs());
            let mut tmp = vault.metrics.fee_budget_surplus.data.write().await;
            *tmp = tmp.saturating_add(surplus);
        }
        publish_fee_budget_surplus(&vault).await;
    }

    publish_bitcoin_balance(&vault);
}

async fn publish_fee_budget_surplus<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    let surplus = *vault.metrics.fee_budget_surplus.data.read().await;
    vault
        .metrics
        .fee_budget_surplus
        .gauge
        .set(surplus as f64 / vault.vault_id.wrapped_currency().one() as f64);
}

async fn publish_average_bitcoin_fee<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    let average = match vault.metrics.average_btc_fee.data.read().await {
        x if x.count > 0 => x.total as f64 / x.count as f64,
        _ => Default::default(),
    };
    vault.metrics.average_btc_fee.gauge.set(average);
}

fn publish_bitcoin_balance<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    match vault.btc_rpc.get_balance(None) {
        Ok(bitcoin_balance) => vault.metrics.btc_balance.actual.set(bitcoin_balance.as_btc() as f64),
        Err(e) => {
            // unexpected error, but not critical so just continue
            tracing::warn!("Failed to get Bitcoin balance: {}", e);
        }
    }
}

async fn publish_native_currency_balance(parachain_rpc: &InterBtcParachain) {
    if let Ok(balance) = parachain_rpc.get_free_balance(parachain_rpc.native_currency_id).await {
        let balance = raw_value_as_currency(balance, parachain_rpc.native_currency_id);
        NATIVE_CURRENCY_BALANCE.set(balance);
    }
}

fn publish_utxo_count<B: BitcoinCoreApi + Clone + Send + Sync>(vault: &VaultData<B>) {
    if let Ok(count) = vault.btc_rpc.get_utxo_count() {
        if let Ok(count_i64) = count.try_into() {
            vault.metrics.utxo_count.set(count_i64);
        }
    }
}

async fn publish_issue_count<B: BitcoinCoreApi + Clone + Send + Sync>(
    parachain_rpc: &InterBtcParachain,
    vault_id_manager: &VaultIdManager<B>,
) {
    if let Ok(issues) = parachain_rpc
        .get_vault_issue_requests(parachain_rpc.get_account_id().clone())
        .await
    {
        for vault in vault_id_manager.get_entries().await {
            let relevant_issues: Vec<_> = issues
                .iter()
                .filter(|(_, issue)| issue.vault == vault.vault_id)
                .map(|(_, issue)| issue.status.clone())
                .collect();

            vault.metrics.issues.open_count.set(
                relevant_issues
                    .iter()
                    .filter(|status| matches!(status, IssueRequestStatus::Pending))
                    .count() as f64,
            );
            vault.metrics.issues.completed_count.set(
                relevant_issues
                    .iter()
                    .filter(|status| matches!(status, IssueRequestStatus::Completed(_)))
                    .count() as f64,
            );
            vault.metrics.issues.expired_count.set(
                relevant_issues
                    .iter()
                    .filter(|status| matches!(status, IssueRequestStatus::Cancelled))
                    .count() as f64,
            );
        }
    }
}

async fn publish_redeem_count<B: BitcoinCoreApi + Clone + Send + Sync>(
    parachain_rpc: &InterBtcParachain,
    vault_id_manager: &VaultIdManager<B>,
) {
    if let Ok(redeems) = parachain_rpc
        .get_vault_redeem_requests(parachain_rpc.get_account_id().clone())
        .await
    {
        for vault in vault_id_manager.get_entries().await {
            let relevant_redeems: Vec<_> = redeems
                .iter()
                .filter(|(_, redeem)| redeem.vault == vault.vault_id)
                .map(|(_, redeem)| redeem.status.clone())
                .collect();

            vault.metrics.redeems.open_count.set(
                relevant_redeems
                    .iter()
                    .filter(|status| matches!(status, RedeemRequestStatus::Pending))
                    .count() as f64,
            );
            vault.metrics.redeems.completed_count.set(
                relevant_redeems
                    .iter()
                    .filter(|status| matches!(status, RedeemRequestStatus::Completed))
                    .count() as f64,
            );
            vault.metrics.redeems.expired_count.set(
                relevant_redeems
                    .iter()
                    .filter(|status| {
                        matches!(
                            status,
                            RedeemRequestStatus::Reimbursed(_) | RedeemRequestStatus::Retried
                        )
                    })
                    .count() as f64,
            );
        }
    }
}

pub async fn monitor_bridge_metrics<B: BitcoinCoreApi + Clone + Send + Sync>(
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let vault_id_manager = &vault_id_manager;
    parachain_rpc
        .on_event::<FeedValuesEvent, _, _, _>(
            |event| async move {
                let updated_currencies = event.values.iter().filter_map(|(key, _value)| match key {
                    OracleKey::ExchangeRate(currency_id) => Some(currency_id),
                    _ => None,
                });
                let vaults = vault_id_manager.get_entries().await;
                for currency_id in updated_currencies {
                    for vault in vaults
                        .iter()
                        .filter(|vault| &vault.vault_id.collateral_currency() == currency_id)
                    {
                        publish_locked_collateral(vault, parachain_rpc.clone()).await;
                        publish_required_collateral(vault, parachain_rpc.clone()).await;
                        publish_collateralization(vault, parachain_rpc.clone()).await;
                    }
                }
            },
            |error| tracing::error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

pub async fn poll_metrics<B: BitcoinCoreApi + Clone + Send + Sync>(
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager<B>,
) -> Result<(), ServiceError> {
    let parachain_rpc = &parachain_rpc;
    let vault_id_manager = &vault_id_manager;

    loop {
        publish_native_currency_balance(&parachain_rpc).await;
        publish_issue_count(&parachain_rpc.clone(), &vault_id_manager).await;
        publish_redeem_count(&parachain_rpc.clone(), &vault_id_manager).await;

        for vault in vault_id_manager.get_entries().await {
            publish_utxo_count(&vault);
        }

        sleep(SLEEP_DURATION).await;
    }
}

pub async fn publish_expected_bitcoin_balance<B: BitcoinCoreApi + Clone + Send + Sync>(
    vault: &VaultData<B>,
    parachain_rpc: InterBtcParachain,
) {
    if let Ok(v) = parachain_rpc.get_vault(&vault.vault_id).await {
        let lowerbound = v.issued_tokens.saturating_sub(v.to_be_redeemed_tokens);
        let upperbound = v.issued_tokens.saturating_add(v.to_be_issued_tokens);
        let scaling_factor = vault.vault_id.wrapped_currency().one() as f64;
        vault
            .metrics
            .btc_balance
            .lowerbound
            .set(lowerbound as f64 / scaling_factor);
        vault
            .metrics
            .btc_balance
            .upperbound
            .set(upperbound as f64 / scaling_factor);
    }
}
