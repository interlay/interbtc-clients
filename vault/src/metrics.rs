use std::{collections::HashMap, convert::TryInto, sync::Arc};

use crate::{
    execution::parachain_blocks_to_bitcoin_blocks_rounded_up,
    system::{VaultData, VaultIdManager},
    Error,
};
use async_trait::async_trait;
use bitcoin::{json::ListTransactionResult, GetTransactionResultDetailCategory, SignedAmount, TransactionExt};
use futures::{try_join, StreamExt, TryFutureExt};
use lazy_static::lazy_static;
use runtime::{
    prometheus::{
        gather, proto::MetricFamily, Encoder, Gauge, GaugeVec, IntCounter, IntGauge, IntGaugeVec, Opts, Registry,
        TextEncoder,
    },
    CollateralBalancesPallet, CurrencyId, CurrencyIdExt, Error as RuntimeError, FeedValuesEvent, FixedU128,
    InterBtcParachain, InterBtcRedeemRequest, IssuePallet, IssueRequestStatus, OracleKey, RedeemPallet,
    RedeemRequestStatus, ReplacePallet, RuntimeCurrencyInfo, SecurityPallet, UtilFuncs, VaultId, VaultRegistryPallet,
    H256,
};
use service::{
    warp::{Rejection, Reply},
    DynBitcoinCoreApi, Error as ServiceError,
};
use std::time::Duration;
use tokio::{sync::RwLock, time::sleep};
use tokio_metrics::TaskMetrics;

const SLEEP_DURATION: Duration = Duration::from_secs(5 * 60);
const SECONDS_PER_HOUR: f64 = 3600.0;

const CURRENCY_LABEL: &str = "currency";
const EXPECTED_BTC_BALANCE_TYPE_LABEL: &str = "type";
const REQUEST_STATUS_LABEL: &str = "status";
const TASK_NAME: &str = "task";
const TOKIO_POLLING_INTERVAL_MS: u64 = 10000;

// Metrics are stored under the [`CURRENCY_LABEL`] key so that multiple vaults can be easily
// monitored at the same time.
lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref REMAINING_TIME_TO_REDEEM_HOURS: GaugeVec = GaugeVec::new(
        Opts::new("remaining_time_to_redeem_hours", "Number of hours to redeem deadline"),
        &[CURRENCY_LABEL]
    )
    .expect("Failed to create prometheus metric");
    pub static ref AVERAGE_BTC_FEE: StatefulGauge<AverageTracker> = StatefulGauge {
        gauge: Gauge::new("avg_btc_fee", "Average Bitcoin Fee").expect("Failed to create prometheus metric"),
        data: Arc::new(RwLock::new(AverageTracker { total: 0, count: 0 })),
    };
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
    pub static ref MEAN_IDLE_DURATION: IntGaugeVec =
        IntGaugeVec::new(Opts::new("mean_idle_duration_ms", "Total Idle Duration"), &[TASK_NAME])
            .expect("Failed to create prometheus metric");
    pub static ref MEAN_POLL_DURATION: IntGaugeVec =
        IntGaugeVec::new(Opts::new("mean_poll_duration_ms", "Total Poll Duration"), &[TASK_NAME])
            .expect("Failed to create prometheus metric");
    pub static ref MEAN_SCHEDULED_DURATION: IntGaugeVec = IntGaugeVec::new(
        Opts::new("mean_scheduled_duration_ms", "Total Scheduled Duration"),
        &[TASK_NAME]
    )
    .expect("Failed to create prometheus metric");
    pub static ref UTXO_COUNT: IntGauge =
        IntGauge::new("utxo_count", "Number of Unspent Bitcoin Outputs",).expect("Failed to create prometheus metric");
    pub static ref ACTUAL_BTC_BALANCE: Gauge =
        Gauge::new("actual_btc_balance", "Actual Bitcoin Balance",).expect("Failed to create prometheus metric");
    pub static ref EXPECTED_BTC_BALANCE: GaugeVec = GaugeVec::new(
        Opts::new("expected_btc_balance", "Expected Bitcoin Balance"),
        &[CURRENCY_LABEL, EXPECTED_BTC_BALANCE_TYPE_LABEL]
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
    pub static ref FEE_BUDGET_SURPLUS: StatefulGauge<i64> = StatefulGauge {
        gauge: Gauge::new("fee_budget_surplus", "Fee Budget Surplus").expect("Failed to create prometheus metric"),
        data: Arc::new(RwLock::new(0)),
    };
    pub static ref RESTART_COUNT: IntCounter =
        IntCounter::new("restart_count", "Number of service restarts").expect("Failed to create prometheus metric");
}

#[derive(Clone, Debug)]
pub struct AverageTracker {
    total: u64,
    count: u64,
}

#[derive(Clone, Debug)]
pub struct StatefulGauge<T: Clone> {
    gauge: Gauge,
    data: Arc<RwLock<T>>,
}

#[derive(Clone, Debug)]
struct BtcBalance {
    upperbound: Gauge,
    lowerbound: Gauge,
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
    remaining_time_to_redeem_hours: Gauge,
    btc_balance: BtcBalance,
    issues: RequestCounter,
    redeems: RequestCounter,
}

#[async_trait]
pub trait VaultDataReader {
    async fn get_entries(&self) -> Vec<VaultData>;
}

#[async_trait]
impl VaultDataReader for VaultIdManager {
    async fn get_entries(&self) -> Vec<VaultData> {
        self.get_entries().await
    }
}

impl PerCurrencyMetrics {
    pub fn new(vault_id: &VaultId) -> Self {
        Self::new_with_label(Self::label(vault_id).as_ref())
    }

    pub fn label(vault_id: &VaultId) -> String {
        format!(
            "{}_{}",
            vault_id.collateral_currency().symbol().unwrap_or_default(),
            vault_id.wrapped_currency().symbol().unwrap_or_default()
        )
    }

    // construct a dummy metrics struct for testing purposes
    pub fn dummy() -> Self {
        Self::new_with_label("dummy")
    }

    fn new_with_label(label: &str) -> Self {
        let labels = HashMap::from([(CURRENCY_LABEL, label)]);

        let expected_btc_balance_gauge = |balance_type: &'static str| {
            let labels =
                HashMap::<&str, &str>::from([(CURRENCY_LABEL, label), (EXPECTED_BTC_BALANCE_TYPE_LABEL, balance_type)]);
            EXPECTED_BTC_BALANCE.with(&labels)
        };
        let request_type_label = |balance_type: &'static str| {
            HashMap::<&str, &str>::from([(CURRENCY_LABEL, label), (REQUEST_STATUS_LABEL, balance_type)])
        };

        Self {
            locked_collateral: LOCKED_COLLATERAL.with(&labels),
            collateralization: COLLATERALIZATION.with(&labels),
            required_collateral: REQUIRED_COLLATERAL.with(&labels),
            remaining_time_to_redeem_hours: REMAINING_TIME_TO_REDEEM_HOURS.with(&labels),
            btc_balance: BtcBalance {
                upperbound: expected_btc_balance_gauge("required_upperbound"),
                lowerbound: expected_btc_balance_gauge("required_lowerbound"),
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

    async fn initialize_fee_budget_surplus<P: VaultRegistryPallet + RedeemPallet + ReplacePallet>(
        vault: &VaultData,
        parachain_rpc: P,
        bitcoin_transactions: Vec<ListTransactionResult>,
    ) -> Result<(), ServiceError<Error>> {
        let vault_id = &vault.vault_id;
        // update fee surplus
        if let Ok((redeem_requests, replace_requests)) = try_join!(
            parachain_rpc.get_vault_redeem_requests(vault_id.account_id.clone()),
            parachain_rpc.get_old_vault_replace_requests(vault_id.account_id.clone())
        ) {
            let redeems = redeem_requests
                .iter()
                .map(|(id, redeem)| (*id, redeem.transfer_fee_btc));
            let replaces = replace_requests.iter().map(|(id, _)| (*id, 0));
            let fee_budgets = redeems.chain(replaces).collect::<HashMap<_, _>>();
            let fee_budgets = &fee_budgets;

            let fee_budget_surplus = futures::stream::iter(bitcoin_transactions.iter())
                .filter_map(|tx| async move {
                    let transaction = vault
                        .btc_rpc
                        .get_transaction(&tx.info.txid, tx.info.blockhash)
                        .await
                        .ok()?;
                    let op_return = transaction.get_op_return()?;
                    let budget: i64 = (*fee_budgets.get(&op_return)?).try_into().ok()?;

                    // give any outer `select` a chance to check the shutdown/termination signal
                    tokio::task::yield_now().await;

                    budget.checked_sub(tx.detail.fee?.to_sat().abs())
                })
                .fold(0i64, |acc, x| async move { acc.saturating_add(x) })
                .await;

            *FEE_BUDGET_SURPLUS.data.write().await = fee_budget_surplus;
            publish_fee_budget_surplus(vault).await?;
        }
        Ok(())
    }

    pub async fn initialize_values(parachain_rpc: InterBtcParachain, vault: &VaultData) {
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
            .filter_map(|tx| tx.detail.fee.map(|amount| amount.to_sat().unsigned_abs()))
            .fold((0, 0), |(total, count), x| (total + x, count + 1));
        *AVERAGE_BTC_FEE.data.write().await = AverageTracker { total, count };

        publish_utxo_count(&vault.btc_rpc);
        publish_bitcoin_balance(&vault.btc_rpc);

        let _ = tokio::join!(
            Self::initialize_fee_budget_surplus(vault, parachain_rpc.clone(), bitcoin_transactions),
            publish_average_bitcoin_fee(),
            publish_expected_bitcoin_balance(vault, parachain_rpc.clone()),
            publish_locked_collateral(vault, &parachain_rpc),
            publish_required_collateral(vault, &parachain_rpc),
            publish_collateralization(vault, &parachain_rpc),
        );
    }
}

pub fn register_custom_metrics() -> Result<(), RuntimeError> {
    REGISTRY.register(Box::new(AVERAGE_BTC_FEE.gauge.clone()))?;
    REGISTRY.register(Box::new(LOCKED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(COLLATERALIZATION.clone()))?;
    REGISTRY.register(Box::new(REQUIRED_COLLATERAL.clone()))?;
    REGISTRY.register(Box::new(FEE_BUDGET_SURPLUS.gauge.clone()))?;
    REGISTRY.register(Box::new(ACTUAL_BTC_BALANCE.clone()))?;
    REGISTRY.register(Box::new(EXPECTED_BTC_BALANCE.clone()))?;
    REGISTRY.register(Box::new(NATIVE_CURRENCY_BALANCE.clone()))?;
    REGISTRY.register(Box::new(ISSUES.clone()))?;
    REGISTRY.register(Box::new(REDEEMS.clone()))?;
    REGISTRY.register(Box::new(UTXO_COUNT.clone()))?;
    REGISTRY.register(Box::new(MEAN_IDLE_DURATION.clone()))?;
    REGISTRY.register(Box::new(MEAN_POLL_DURATION.clone()))?;
    REGISTRY.register(Box::new(MEAN_SCHEDULED_DURATION.clone()))?;
    REGISTRY.register(Box::new(REMAINING_TIME_TO_REDEEM_HOURS.clone()))?;
    REGISTRY.register(Box::new(RESTART_COUNT.clone()))?;

    Ok(())
}

fn serialize(metrics: &[MetricFamily]) -> String {
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(metrics, &mut buffer) {
        tracing::error!("Could not encode metrics: {}", e);
    };
    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Metrics could not be parsed `from_utf8`: {}", e);
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

fn raw_value_as_currency(value: u128, currency: CurrencyId) -> Result<f64, ServiceError<Error>> {
    let scaling_factor = currency.one()? as f64;
    Ok(value as f64 / scaling_factor)
}

pub async fn publish_locked_collateral<P: VaultRegistryPallet>(
    vault: &VaultData,
    parachain_rpc: &P,
) -> Result<(), ServiceError<Error>> {
    if let Ok(actual_collateral) = parachain_rpc.get_vault_total_collateral(vault.vault_id.clone()).await {
        let actual_collateral = raw_value_as_currency(actual_collateral, vault.vault_id.collateral_currency())?;
        vault.metrics.locked_collateral.set(actual_collateral);
    }
    Ok(())
}

pub async fn publish_required_collateral<P: VaultRegistryPallet>(
    vault: &VaultData,
    parachain_rpc: &P,
) -> Result<(), ServiceError<Error>> {
    if let Ok(required_collateral) = parachain_rpc
        .get_required_collateral_for_vault(vault.vault_id.clone())
        .await
    {
        let required_collateral = raw_value_as_currency(required_collateral, vault.vault_id.collateral_currency())?;
        vault.metrics.required_collateral.set(required_collateral);
    }
    Ok(())
}

pub async fn publish_collateralization<P: VaultRegistryPallet>(vault: &VaultData, parachain_rpc: &P) {
    // if the collateralization is infinite, return 0 rather than logging an error so
    // the metrics do change in case of a replacement
    let collateralization = parachain_rpc
        .get_collateralization_from_vault(vault.vault_id.clone(), false)
        .await
        .unwrap_or(0u128);
    let float_collateralization_percentage = FixedU128::from_inner(collateralization).to_float();
    vault.metrics.collateralization.set(float_collateralization_percentage);
}

pub async fn update_bitcoin_metrics(
    vault: &VaultData,
    new_fee_entry: Option<SignedAmount>,
    fee_budget: Option<u128>,
) -> Result<(), ServiceError<Error>> {
    // update the average fee
    if let Some(amount) = new_fee_entry {
        {
            let mut tmp = AVERAGE_BTC_FEE.data.write().await;
            *tmp = AverageTracker {
                total: tmp.total.saturating_add(amount.to_sat().unsigned_abs()),
                count: tmp.count.saturating_add(1),
            };
        }
        publish_average_bitcoin_fee().await;

        if let Ok(budget) = TryInto::<i64>::try_into(fee_budget.unwrap_or(0)) {
            let surplus = budget.saturating_sub(amount.to_sat().abs());
            let mut tmp = FEE_BUDGET_SURPLUS.data.write().await;
            *tmp = tmp.saturating_add(surplus);
        }
        publish_fee_budget_surplus(vault).await?;
    }

    publish_bitcoin_balance(&vault.btc_rpc);
    Ok(())
}

async fn publish_fee_budget_surplus(vault: &VaultData) -> Result<(), ServiceError<Error>> {
    let surplus = *FEE_BUDGET_SURPLUS.data.read().await;
    FEE_BUDGET_SURPLUS
        .gauge
        .set(surplus as f64 / vault.vault_id.wrapped_currency().inner()?.one() as f64);
    Ok(())
}

async fn publish_average_bitcoin_fee() {
    let average = match AVERAGE_BTC_FEE.data.read().await {
        x if x.count > 0 => x.total as f64 / x.count as f64,
        _ => Default::default(),
    };
    AVERAGE_BTC_FEE.gauge.set(average);
}

fn publish_bitcoin_balance(btc_rpc: &DynBitcoinCoreApi) {
    match btc_rpc.get_balance(None) {
        Ok(bitcoin_balance) => ACTUAL_BTC_BALANCE.set(bitcoin_balance.to_btc()),
        Err(e) => {
            // unexpected error, but not critical so just continue
            tracing::warn!("Failed to get Bitcoin balance: {}", e);
        }
    }
}

async fn publish_native_currency_balance<P: CollateralBalancesPallet + UtilFuncs>(
    parachain_rpc: &P,
) -> Result<(), ServiceError<Error>> {
    let native_currency = parachain_rpc.get_native_currency_id();
    if let Ok(balance) = parachain_rpc.get_free_balance(native_currency).await {
        let balance = raw_value_as_currency(balance, native_currency)?;
        NATIVE_CURRENCY_BALANCE.set(balance);
    }
    Ok(())
}

fn publish_utxo_count(btc_rpc: &DynBitcoinCoreApi) {
    if let Ok(count) = btc_rpc.get_utxo_count() {
        if let Ok(count_i64) = count.try_into() {
            UTXO_COUNT.set(count_i64);
        }
    }
}

pub fn increment_restart_counter() {
    RESTART_COUNT.inc();
}

async fn publish_issue_count<V: VaultDataReader, P: IssuePallet + UtilFuncs>(parachain_rpc: &P, vault_id_manager: &V) {
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
                    .filter(|status| matches!(status, IssueRequestStatus::Completed))
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

async fn publish_time_to_first_deadline<V: VaultDataReader, P: RedeemPallet + SecurityPallet>(
    parachain_rpc: &P,
    vault_id_manager: &V,
    redeems: &[(H256, InterBtcRedeemRequest)],
) {
    for vault in vault_id_manager.get_entries().await {
        let data: Result<_, Error> = tokio::try_join!(
            parachain_rpc.get_redeem_period().map_err(Into::into),
            parachain_rpc.get_current_active_block_number().map_err(Into::into),
            vault.btc_rpc.get_block_count().map_err(Into::into),
        );
        if let Ok((redeem_period, para_height, bitcoin_height)) = data {
            let remaining_time = redeems
                .iter()
                .filter(|(_, redeem)| redeem.vault == vault.vault_id && redeem.status == RedeemRequestStatus::Pending)
                .filter_map(|(_, redeem)| calculate_remaining_time(redeem_period, redeem, para_height, bitcoin_height))
                .min();

            // if no redeem deadlines, then use the redeem period
            let remaining_time: Duration = remaining_time.unwrap_or_else(|| runtime::BLOCK_INTERVAL * redeem_period);

            vault
                .metrics
                .remaining_time_to_redeem_hours
                .set(remaining_time.as_secs_f64() / SECONDS_PER_HOUR);
        }
    }
}

fn calculate_remaining_time(
    redeem_period: u32,
    redeem: &InterBtcRedeemRequest,
    para_height: u32,
    bitcoin_height: u64,
) -> Option<Duration> {
    let period_parachain_blocks = redeem_period.max(redeem.period);
    let time_to_parachain_deadline = {
        let deadline_block = redeem.opentime.saturating_add(period_parachain_blocks);
        let remaining_blocks = deadline_block.saturating_sub(para_height);
        runtime::BLOCK_INTERVAL * remaining_blocks
    };
    let time_to_bitcoin_deadline = {
        let period_bitcoin_blocks = parachain_blocks_to_bitcoin_blocks_rounded_up(period_parachain_blocks).ok()? as u64;
        let deadline_bitcoin_block = period_bitcoin_blocks.saturating_add(redeem.btc_height as u64);
        let remaining_blocks = deadline_bitcoin_block.saturating_sub(bitcoin_height);
        bitcoin::BLOCK_INTERVAL * remaining_blocks.try_into().ok()?
    };
    Some(time_to_parachain_deadline.max(time_to_bitcoin_deadline))
}

async fn publish_redeem_count<V: VaultDataReader>(vault_id_manager: &V, redeems: &[(H256, InterBtcRedeemRequest)]) {
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

pub async fn monitor_bridge_metrics(
    parachain_rpc: InterBtcParachain,
    vault_id_manager: VaultIdManager,
) -> Result<(), ServiceError<Error>> {
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
                        let _ = tokio::join!(
                            publish_locked_collateral(vault, parachain_rpc),
                            publish_required_collateral(vault, parachain_rpc),
                            publish_collateralization(vault, parachain_rpc),
                        );
                    }
                }
            },
            |error| tracing::error!("Error reading SetExchangeRate event: {}", error.to_string()),
        )
        .await?;
    Ok(())
}

pub async fn poll_metrics<P: CollateralBalancesPallet + RedeemPallet + IssuePallet + SecurityPallet + UtilFuncs>(
    parachain_rpc: P,
    vault_id_manager: VaultIdManager,
) -> Result<(), ServiceError<Error>> {
    let parachain_rpc = &parachain_rpc;
    let vault_id_manager = &vault_id_manager;

    loop {
        publish_native_currency_balance(parachain_rpc).await?;
        publish_issue_count(parachain_rpc, vault_id_manager).await;
        if let Ok(redeems) = parachain_rpc
            .get_vault_redeem_requests(parachain_rpc.get_account_id().clone())
            .await
        {
            publish_redeem_count(vault_id_manager, &redeems).await;
            publish_time_to_first_deadline(parachain_rpc, vault_id_manager, &redeems).await;
        }

        publish_utxo_count(&vault_id_manager.btc_rpc_shared_wallet);

        sleep(SLEEP_DURATION).await;
    }
}

pub async fn publish_expected_bitcoin_balance<P: VaultRegistryPallet>(
    vault: &VaultData,
    parachain_rpc: P,
) -> Result<(), ServiceError<Error>> {
    if let Ok(v) = parachain_rpc.get_vault(&vault.vault_id).await {
        let lowerbound = v.issued_tokens.saturating_sub(v.to_be_redeemed_tokens);
        let upperbound = v.issued_tokens.saturating_add(v.to_be_issued_tokens);
        let scaling_factor = vault.vault_id.wrapped_currency().inner()?.one() as f64;
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
    Ok(())
}

pub async fn publish_tokio_metrics(
    mut metrics_iterators: HashMap<String, impl Iterator<Item = TaskMetrics>>,
) -> Result<(), ServiceError<Error>> {
    let frequency = Duration::from_millis(TOKIO_POLLING_INTERVAL_MS);
    loop {
        for (key, val) in metrics_iterators.iter_mut() {
            if let Some(task_metrics) = val.next() {
                let label = HashMap::<&str, &str>::from([(TASK_NAME, &key[..])]);
                MEAN_IDLE_DURATION
                    .with(&label)
                    .set(task_metrics.mean_idle_duration().as_millis() as i64);
                MEAN_POLL_DURATION
                    .with(&label)
                    .set(task_metrics.mean_poll_duration().as_millis() as i64);
                MEAN_SCHEDULED_DURATION
                    .with(&label)
                    .set(task_metrics.mean_scheduled_duration().as_millis() as i64);
            }
        }
        tokio::time::sleep(frequency).await;
    }
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bitcoin::{
        json, Address, Amount, BitcoinCoreApi, Block, BlockHash, BlockHeader, Error as BitcoinError, Network,
        PrivateKey, PublicKey, RawTransactionProof, SatPerVbyte, Transaction, TransactionMetadata, Txid,
    };
    use jsonrpc_core::serde_json::{Map, Value};
    use runtime::{
        metadata::runtime_types::interbtc_primitives::CustomMetadata,
        subxt::utils::Static,
        AccountId, AssetMetadata, AssetRegistry, Balance, BlockNumber, BtcAddress, BtcPublicKey,
        CurrencyId::{self, ForeignAsset, LendToken},
        Error as RuntimeError, InterBtcIssueRequest, InterBtcRedeemRequest, InterBtcReplaceRequest, InterBtcVault,
        LendingAssets, RequestIssueEvent, Token, VaultId, VaultStatus, DOT, H256, IBTC, INTR,
    };

    mockall::mock! {
        Provider {}

        #[async_trait]
        pub trait UtilFuncs {
            async fn get_current_chain_height(&self) -> Result<u32, RuntimeError>;
            async fn get_rpc_properties(&self) -> Result<Map<String, Value>, RuntimeError>;
            fn get_native_currency_id(&self) -> CurrencyId;
            fn get_account_id(&self) -> &AccountId;
            fn is_this_vault(&self, vault_id: &VaultId) -> bool;
            async fn get_foreign_assets_metadata(&self) -> Result<Vec<(u32, AssetMetadata)>, RuntimeError>;
            async fn get_foreign_asset_metadata(&self, id: u32) -> Result<AssetMetadata, RuntimeError>;
            async fn get_lend_tokens(&self) -> Result<Vec<(CurrencyId, CurrencyId)>, RuntimeError>;
        }

        #[async_trait]
        pub trait IssuePallet {
            async fn request_issue(&self, amount: u128, vault_id: &VaultId) -> Result<RequestIssueEvent, RuntimeError>;
            async fn execute_issue(&self, issue_id: H256, raw_proof: &RawTransactionProof) -> Result<(), RuntimeError>;
            async fn cancel_issue(&self, issue_id: H256) -> Result<(), RuntimeError>;
            async fn get_issue_request(&self, issue_id: H256) -> Result<InterBtcIssueRequest, RuntimeError>;
            async fn get_vault_issue_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcIssueRequest)>, RuntimeError>;
            async fn get_issue_period(&self) -> Result<u32, RuntimeError>;
            async fn get_all_active_issues(&self) -> Result<Vec<(H256, InterBtcIssueRequest)>, RuntimeError>;
        }

        #[async_trait]
        pub trait RedeemPallet {
            async fn request_redeem(&self, amount: u128, btc_address: BtcAddress, vault_id: &VaultId) -> Result<H256, RuntimeError>;
            async fn execute_redeem(&self, redeem_id: H256, raw_proof: &RawTransactionProof) -> Result<(), RuntimeError>;
            async fn cancel_redeem(&self, redeem_id: H256, reimburse: bool) -> Result<(), RuntimeError>;
            async fn get_redeem_request(&self, redeem_id: H256) -> Result<InterBtcRedeemRequest, RuntimeError>;
            async fn get_vault_redeem_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcRedeemRequest)>, RuntimeError>;
            async fn get_redeem_period(&self) -> Result<BlockNumber, RuntimeError>;
        }

        #[async_trait]
        pub trait VaultRegistryPallet {
            async fn get_vault(&self, vault_id: &VaultId) -> Result<InterBtcVault, RuntimeError>;
            async fn get_vaults_by_account_id(&self, account_id: &AccountId) -> Result<Vec<VaultId>, RuntimeError>;
            async fn get_all_vaults(&self) -> Result<Vec<InterBtcVault>, RuntimeError>;
            async fn register_vault(&self, vault_id: &VaultId, collateral: u128) -> Result<(), RuntimeError>;
            async fn deposit_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_collateral(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn get_public_key(&self) -> Result<Option<BtcPublicKey>, RuntimeError>;
            async fn register_public_key(&self, public_key: BtcPublicKey) -> Result<(), RuntimeError>;
            async fn get_required_collateral_for_wrapped(&self, amount_btc: u128, collateral_currency: CurrencyId) -> Result<u128, RuntimeError>;
            async fn get_required_collateral_for_vault(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_vault_total_collateral(&self, vault_id: VaultId) -> Result<u128, RuntimeError>;
            async fn get_collateralization_from_vault(&self, vault_id: VaultId, only_issued: bool) -> Result<u128, RuntimeError>;
            async fn set_current_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
            async fn set_pending_client_release(&self, uri: &[u8], code_hash: &H256) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait CollateralBalancesPallet {
            async fn get_free_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_free_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_reserved_balance(&self, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn get_reserved_balance_for_id(&self, id: AccountId, currency_id: CurrencyId) -> Result<Balance, RuntimeError>;
            async fn transfer_to(&self, recipient: &AccountId, amounts: Vec<(u128, CurrencyId)>) -> Result<(), RuntimeError>;
        }

        #[async_trait]
        pub trait ReplacePallet {
            async fn request_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn withdraw_replace(&self, vault_id: &VaultId, amount: u128) -> Result<(), RuntimeError>;
            async fn accept_replace(&self, new_vault: &VaultId, old_vault: &VaultId, amount_btc: u128, collateral: u128, btc_address: BtcAddress) -> Result<(), RuntimeError>;
            async fn execute_replace(&self, replace_id: H256, raw_proof: &RawTransactionProof) -> Result<(), RuntimeError>;
            async fn cancel_replace(&self, replace_id: H256) -> Result<(), RuntimeError>;
            async fn get_new_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_old_vault_replace_requests(&self, account_id: AccountId) -> Result<Vec<(H256, InterBtcReplaceRequest)>, RuntimeError>;
            async fn get_replace_period(&self) -> Result<u32, RuntimeError>;
            async fn get_replace_request(&self, replace_id: H256) -> Result<InterBtcReplaceRequest, RuntimeError>;
            async fn get_replace_dust_amount(&self) -> Result<u128, RuntimeError>;
        }

        #[async_trait]
        pub trait SecurityPallet {
            /// Gets the current active block number of the parachain
            async fn get_current_active_block_number(&self) -> Result<u32, RuntimeError>;
        }
    }

    impl Clone for MockProvider {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    mockall::mock! {
        Bitcoin {}

        #[async_trait]
        trait BitcoinCoreApi {
            fn is_full_node(&self) -> bool;
            fn network(&self) -> Network;
            async fn wait_for_block(&self, height: u32, num_confirmations: u32) -> Result<Block, BitcoinError>;
            fn get_balance(&self, min_confirmations: Option<u32>) -> Result<Amount, BitcoinError>;
            fn list_transactions(&self, max_count: Option<usize>) -> Result<Vec<json::ListTransactionResult>, BitcoinError>;
            fn list_addresses(&self) -> Result<Vec<Address>, BitcoinError>;
            async fn get_block_count(&self) -> Result<u64, BitcoinError>;
            async fn get_raw_tx(&self, txid: &Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_transaction(&self, txid: &Txid, block_hash: Option<BlockHash>) -> Result<Transaction, BitcoinError>;
            async fn get_proof(&self, txid: Txid, block_hash: &BlockHash) -> Result<Vec<u8>, BitcoinError>;
            async fn get_block_hash(&self, height: u32) -> Result<BlockHash, BitcoinError>;
            async fn get_pruned_height(&self) -> Result<u64, BitcoinError>;
            async fn get_new_address(&self) -> Result<Address, BitcoinError>;
            async fn get_new_public_key(&self) -> Result<PublicKey, BitcoinError>;
            fn dump_private_key(&self, address: &Address) -> Result<PrivateKey, BitcoinError>;
            fn import_private_key(&self, private_key: &PrivateKey, is_derivation_key: bool) -> Result<(), BitcoinError>;
            async fn add_new_deposit_key(&self, public_key: PublicKey, secret_key: Vec<u8>) -> Result<(), BitcoinError>;
            async fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinError>;
            async fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinError>;
            async fn get_block_header(&self, hash: &BlockHash) -> Result<BlockHeader, BitcoinError>;
            async fn get_mempool_transactions<'a>(&'a self) -> Result<Box<dyn Iterator<Item = Result<Transaction, BitcoinError>> + Send + 'a>, BitcoinError>;
            async fn wait_for_transaction_metadata(&self, txid: Txid, num_confirmations: u32, block_hash: Option<BlockHash>, is_wallet: bool) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_and_send_transaction(&self, address: Address, sat: u64, fee_rate: SatPerVbyte, request_id: Option<H256>) -> Result<Txid, BitcoinError>;
            async fn send_to_address(&self, address: Address, sat: u64, request_id: Option<H256>, fee_rate: SatPerVbyte, num_confirmations: u32) -> Result<TransactionMetadata, BitcoinError>;
            async fn create_or_load_wallet(&self) -> Result<(), BitcoinError>;
            async fn rescan_blockchain(&self, start_height: usize, end_height: usize) -> Result<(), BitcoinError>;
            async fn rescan_electrs_for_addresses(&self, addresses: Vec<Address>) -> Result<(), BitcoinError>;
            fn get_utxo_count(&self) -> Result<usize, BitcoinError>;
            async fn bump_fee(
                &self,
                txid: &Txid,
                address: Address,
                fee_rate: SatPerVbyte,
            ) -> Result<Txid, BitcoinError>;
            async fn is_in_mempool(&self, txid: Txid) -> Result<bool, BitcoinError>;
            async fn fee_rate(&self, txid: Txid) -> Result<SatPerVbyte, BitcoinError>;
            async fn get_tx_for_op_return(&self, address: Address, amount: u128, data: H256) -> Result<Option<Txid>, BitcoinError>;
        }
    }

    mockall::mock! {
        VaultIdManager {}

        #[async_trait]
        trait VaultDataReader {
            async fn get_entries(&self) -> Vec<VaultData>;
        }
    }

    impl Clone for MockBitcoin {
        fn clone(&self) -> Self {
            // NOTE: expectations dropped
            Self::default()
        }
    }

    fn dummy_vault_id() -> VaultId {
        VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(IBTC))
    }

    struct MockProviderBuilder {
        required: u128,
        actual: u128,
        max: u128,
        issued_tokens: u128,
        to_be_issued_tokens: u128,
        to_be_redeemed_tokens: u128,
    }

    impl MockProviderBuilder {
        pub fn new() -> Self {
            Self {
                required: 0,
                actual: 0,
                max: 0,
                issued_tokens: 0,
                to_be_issued_tokens: 0,
                to_be_redeemed_tokens: 0,
            }
        }

        pub fn set_required_collateral(mut self, required: u128) -> Self {
            self.required = required;
            self
        }

        pub fn set_actual_collateral(mut self, actual: u128) -> Self {
            self.actual = actual;
            self
        }

        pub fn set_max_free_balance(mut self, max: u128) -> Self {
            self.max = max;
            self
        }

        pub fn set_issued_tokens(mut self, issued_tokens: u128) -> Self {
            self.issued_tokens = issued_tokens;
            self
        }

        pub fn set_to_be_issued_tokens(mut self, to_be_issued_tokens: u128) -> Self {
            self.to_be_issued_tokens = to_be_issued_tokens;
            self
        }

        pub fn set_to_be_redeemed_tokens(mut self, to_be_redeemed_tokens: u128) -> Self {
            self.to_be_redeemed_tokens = to_be_redeemed_tokens;
            self
        }

        pub fn build(&self) -> MockProvider {
            setup_mocks(
                self.required,
                self.actual,
                self.max,
                self.issued_tokens,
                self.to_be_issued_tokens,
                self.to_be_redeemed_tokens,
            )
        }
    }

    fn setup_mocks(
        required: u128,
        actual: u128,
        max: u128,
        issued_tokens: u128,
        to_be_issued_tokens: u128,
        to_be_redeemed_tokens: u128,
    ) -> MockProvider {
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_required_collateral_for_vault()
            .returning(move |_| Ok(required));

        parachain_rpc.expect_get_vault().returning(move |x| {
            Ok(InterBtcVault {
                id: x.clone(),
                status: VaultStatus::Active(true),
                banned_until: None,
                secure_collateral_threshold: None,
                to_be_issued_tokens,
                issued_tokens,
                to_be_redeemed_tokens,
                to_be_replaced_tokens: 0,
                replace_collateral: 0,
                liquidated_collateral: 0,
                active_replace_collateral: 0,
            })
        });

        parachain_rpc
            .expect_get_vault_total_collateral()
            .returning(move |_| Ok(actual));

        parachain_rpc
            .expect_get_free_balance()
            .returning(move |_| Ok(if max > actual { max - actual } else { 0 }));

        parachain_rpc
    }

    fn dummy_issue_request(status: IssueRequestStatus, vault: VaultId) -> InterBtcIssueRequest {
        InterBtcIssueRequest {
            amount: Default::default(),
            btc_address: Static(Default::default()),
            btc_height: Default::default(),
            fee: Default::default(),
            griefing_collateral: Default::default(),
            griefing_currency: Token(INTR),
            opentime: Default::default(),
            period: Default::default(),
            requester: AccountId::new([1u8; 32]),
            btc_public_key: BtcPublicKey { 0: [0; 33] },
            status,
            vault,
        }
    }

    fn dummy_redeem_request(status: RedeemRequestStatus, vault: VaultId) -> InterBtcRedeemRequest {
        InterBtcRedeemRequest {
            amount_btc: Default::default(),
            btc_address: Static(Default::default()),
            btc_height: Default::default(),
            fee: Default::default(),
            transfer_fee_btc: Default::default(),
            premium: Default::default(),
            opentime: Default::default(),
            period: Default::default(),
            redeemer: AccountId::new([1u8; 32]),
            status,
            vault,
        }
    }

    #[tokio::test]
    async fn test_metrics_average_bitcoin_balance_bounds() {
        let parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();
        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        publish_expected_bitcoin_balance(&vault_data, parachain_rpc)
            .await
            .unwrap();
        let bitcoin_lower_bound = vault_data.metrics.btc_balance.lowerbound.get();
        let bitcoin_upper_bound = vault_data.metrics.btc_balance.upperbound.get();

        assert_eq!(bitcoin_lower_bound, 9.0);
        assert_eq!(bitcoin_upper_bound, 13.0);
    }

    #[tokio::test]
    async fn test_metrics_restart_counter() {
        assert_eq!(RESTART_COUNT.get(), 0);
        increment_restart_counter();
        assert_eq!(RESTART_COUNT.get(), 1);
    }

    #[tokio::test]
    async fn test_bitcoin_metrics() {
        let mut mock_bitcoin = MockBitcoin::default();
        mock_bitcoin
            .expect_get_balance()
            .returning(move |_| Ok(Amount::from_btc(3.0).unwrap()));
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        update_bitcoin_metrics(&vault_data, Some(SignedAmount::from_sat(125)), Some(122))
            .await
            .unwrap();
        let average_btc_fee = AVERAGE_BTC_FEE.gauge.get();
        let fee_budget_surplus = FEE_BUDGET_SURPLUS.gauge.get();
        let bitcoin_balance = ACTUAL_BTC_BALANCE.get();

        assert_eq!(average_btc_fee, 125.0);
        assert_eq!(fee_budget_surplus, -0.00000003);
        assert_eq!(bitcoin_balance, 3.0);
    }

    #[tokio::test]
    async fn test_utxo_count() {
        let mut mock_bitcoin = MockBitcoin::default();
        mock_bitcoin.expect_get_utxo_count().returning(move || Ok(102));
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);
        publish_utxo_count(&btc_rpc);
        let utxo_count = UTXO_COUNT.get();
        assert_eq!(utxo_count, 102);
    }

    #[tokio::test]
    async fn test_metrics_total_collateral() {
        let parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();
        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        publish_locked_collateral(&vault_data, &parachain_rpc).await.unwrap();
        let total_collateral = vault_data.metrics.locked_collateral.get();

        assert_eq!(total_collateral, 0.0000000075);
    }

    #[tokio::test]
    async fn test_foreign_asset_collateral() {
        let dummy_metadata = AssetMetadata {
            decimals: 10,
            location: None,
            name: b"Tether USD".to_vec(),
            symbol: b"USDT".to_vec(),
            existential_deposit: 0,
            additional: CustomMetadata {
                fee_per_second: 0,
                coingecko_id: vec![],
            },
        };
        AssetRegistry::insert(1, dummy_metadata).unwrap();
        let vault_id = VaultId::new(AccountId::new([1u8; 32]), ForeignAsset(1), Token(IBTC));
        assert_eq!(PerCurrencyMetrics::label(&vault_id).to_string(), "USDT_IBTC");
    }

    #[tokio::test]
    async fn test_token_collateral() {
        let vault_id = VaultId::new(AccountId::new([1u8; 32]), Token(DOT), Token(IBTC));
        assert_eq!(PerCurrencyMetrics::label(&vault_id).to_string(), "DOT_IBTC");
    }

    #[tokio::test]
    async fn test_lend_token_collateral() {
        LendingAssets::insert(Token(DOT), LendToken(1)).unwrap();
        let vault_id = VaultId::new(AccountId::new([1u8; 32]), LendToken(1), Token(IBTC));
        assert_eq!(PerCurrencyMetrics::label(&vault_id).to_string(), "QDOT_IBTC");
    }

    #[tokio::test]
    async fn test_metrics_collateralization() {
        let collateralization = 150;
        let mut parachain_rpc = MockProvider::default();
        parachain_rpc
            .expect_get_collateralization_from_vault()
            .returning(move |_, _| Ok(collateralization));
        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        publish_collateralization(&vault_data, &parachain_rpc).await;
        let collateralization_metrics = vault_data.metrics.collateralization.get();

        assert_eq!(
            collateralization_metrics,
            FixedU128::from_inner(collateralization).to_float()
        );
    }

    #[tokio::test]
    async fn test_metrics_required_collateral() {
        let parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();

        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        publish_required_collateral(&vault_data, &parachain_rpc).await.unwrap();
        let required_collateral = vault_data.metrics.required_collateral.get();

        assert_eq!(required_collateral, 0.000000005);
    }

    #[tokio::test]
    async fn test_metrics_native_currency_balance() {
        let mut parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();

        parachain_rpc
            .expect_get_native_currency_id()
            .returning(move || Token(INTR));

        publish_native_currency_balance(&parachain_rpc).await.unwrap();

        let native_currency_balance = NATIVE_CURRENCY_BALANCE.get();
        assert_eq!(native_currency_balance, 0.0000000025);
    }

    #[tokio::test]
    async fn test_metrics_issue_count() {
        let mut parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();
        parachain_rpc.expect_get_vault_issue_requests().returning(move |_| {
            Ok(vec![
                (
                    H256::default(),
                    dummy_issue_request(IssueRequestStatus::Pending, dummy_vault_id()),
                ),
                (
                    H256::default(),
                    dummy_issue_request(IssueRequestStatus::Completed, dummy_vault_id()),
                ),
                (
                    H256::default(),
                    dummy_issue_request(IssueRequestStatus::Cancelled, dummy_vault_id()),
                ),
            ])
        });

        parachain_rpc
            .expect_get_account_id()
            .return_const(AccountId::new([1u8; 32]));

        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        let mut vault_id_manager = MockVaultIdManager::default();
        let vault_data_clone = vault_data.clone();
        vault_id_manager
            .expect_get_entries()
            .returning(move || vec![vault_data_clone.clone()]);

        publish_issue_count(&parachain_rpc, &vault_id_manager).await;

        let open_issues = vault_data.metrics.issues.open_count.get();
        assert_eq!(open_issues, 1.0);

        let completed_issues = vault_data.metrics.issues.completed_count.get();
        assert_eq!(completed_issues, 1.0);

        let cancelled_issues = vault_data.metrics.issues.expired_count.get();
        assert_eq!(cancelled_issues, 1.0);
    }

    #[tokio::test]
    async fn test_metrics_redeem_count() {
        let mut parachain_rpc = MockProviderBuilder::new()
            .set_required_collateral(50)
            .set_actual_collateral(75)
            .set_max_free_balance(100)
            .set_issued_tokens(1200000000)
            .set_to_be_issued_tokens(100000000)
            .set_to_be_redeemed_tokens(300000000)
            .build();
        let redeems = vec![
            (
                H256::default(),
                dummy_redeem_request(RedeemRequestStatus::Pending, dummy_vault_id()),
            ),
            (
                H256::default(),
                dummy_redeem_request(RedeemRequestStatus::Completed, dummy_vault_id()),
            ),
            (
                H256::default(),
                dummy_redeem_request(RedeemRequestStatus::Reimbursed(false), dummy_vault_id()),
            ),
        ];

        parachain_rpc
            .expect_get_account_id()
            .return_const(AccountId::new([1u8; 32]));

        let mock_bitcoin = MockBitcoin::default();
        let btc_rpc: DynBitcoinCoreApi = Arc::new(mock_bitcoin);

        let vault_data = VaultData {
            vault_id: dummy_vault_id(),
            btc_rpc,
            metrics: PerCurrencyMetrics::dummy(),
        };

        let mut vault_id_manager = MockVaultIdManager::default();
        let vault_data_clone = vault_data.clone();
        vault_id_manager
            .expect_get_entries()
            .returning(move || vec![vault_data_clone.clone()]);

        publish_redeem_count(&vault_id_manager, &redeems).await;

        let open_redeems = vault_data.metrics.redeems.open_count.get();
        assert_eq!(open_redeems, 1.0);

        let completed_redeems = vault_data.metrics.redeems.completed_count.get();
        assert_eq!(completed_redeems, 1.0);

        let cancelled_redeems = vault_data.metrics.redeems.expired_count.get();
        assert_eq!(cancelled_redeems, 1.0);
    }

    #[test]
    fn test_calculate_remaining_time() {
        let full_duration = Duration::from_secs(3600 * 24); // redeem deadline set to 24 hours
        let parachain_blocks_per_bitcoin_block = bitcoin::BLOCK_INTERVAL.as_secs() / runtime::BLOCK_INTERVAL.as_secs();

        let redeem_period_para_blocks = (full_duration.as_secs() / runtime::BLOCK_INTERVAL.as_secs()) as u32;
        let redeem_period_btc_blocks = redeem_period_para_blocks as u64 / parachain_blocks_per_bitcoin_block;

        #[derive(Clone, Copy)]
        struct Params {
            local_redeem_period: u32,
            para_current_height: u32,
            btc_current_height: u64,
        }

        let remaining_time = |Params {
                                  local_redeem_period,
                                  para_current_height,
                                  btc_current_height,
                              }| {
            // add arbitrary offset for starting heights for better coverage
            let para_open_height = 12345;
            let btc_open_height = 56789;
            let redeem = InterBtcRedeemRequest {
                opentime: para_open_height,
                btc_height: btc_open_height,
                period: local_redeem_period,
                ..dummy_redeem_request(RedeemRequestStatus::Pending, dummy_vault_id())
            };
            calculate_remaining_time(
                redeem_period_para_blocks,
                &redeem,
                para_open_height + para_current_height,
                btc_open_height as u64 + btc_current_height,
            )
        };

        // setup the default params: local_redeem_period < global_redeem_period
        // and the current height is such that the redeem just expired.
        let testing_params = Params {
            local_redeem_period: redeem_period_para_blocks / 2,
            para_current_height: redeem_period_para_blocks,
            btc_current_height: redeem_period_btc_blocks,
        };

        assert_eq!(remaining_time(testing_params), Some(Duration::ZERO));

        // test impact of current parachain height:
        // if only 1/4th of the para blocks have been produced (and bitcoin deadline has already been reached)
        // then the remaining time is 3/4th of a day
        assert_eq!(
            remaining_time(Params {
                para_current_height: redeem_period_para_blocks / 4,
                ..testing_params
            }),
            Some((full_duration * 3) / 4)
        );

        // test impact of current bitcoin height:
        // if only 1/4th of the bitcoin blocks have been produced (and parachain deadline has already been reached)
        // then the remaining time is 3/4th of a day
        assert_eq!(
            remaining_time(Params {
                btc_current_height: redeem_period_btc_blocks / 4,
                ..testing_params
            }),
            Some((full_duration * 3) / 4)
        );

        // test impact of local redeem period:
        // if 1 day worth of blocks have been produced, but the local redeem period is set to 4 days,
        // then we have 3 days remaining
        assert_eq!(
            remaining_time(Params {
                local_redeem_period: redeem_period_para_blocks * 4,
                ..testing_params
            }),
            Some(full_duration * 3)
        );
    }
}
