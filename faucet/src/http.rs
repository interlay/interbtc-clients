use crate::{error::Error, Allowance, AllowanceAmount, AllowanceConfig};
use chrono::{DateTime, Duration as ISO8601, Utc};
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{serde_json::Value, Error as JsonRpcError, ErrorCode as JsonRpcErrorCode, IoHandler, Params},
    DomainsValidation, ServerBuilder,
};
use kv::*;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    AccountId, CollateralBalancesPallet, CurrencyId, Error as RuntimeError, InterBtcParachain, RuntimeCurrencyInfo,
    TryFromSymbol, VaultRegistryPallet,
};
use serde::{Deserialize, Deserializer};
use std::{net::SocketAddr, time::Duration};
use tokio::time::timeout;

const HEALTH_DURATION: Duration = Duration::from_millis(5000);
const KV_STORE_NAME: &str = "store";

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
struct FaucetRequest {
    datetime: String,
    account_type: FundingRequestAccountType,
}

#[derive(Debug, Clone, Deserialize)]
struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string())))
}

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(err) => Err(JsonRpcError {
            code: JsonRpcErrorCode::InternalError,
            message: err.to_string(),
            data: None,
        }),
    }
}

async fn _system_health(parachain_rpc: &InterBtcParachain) -> Result<(), Error> {
    match timeout(HEALTH_DURATION, parachain_rpc.get_finalized_block_hash()).await {
        Err(err) => Err(Error::RuntimeError(RuntimeError::from(err))),
        _ => Ok(()),
    }
}

#[derive(Encode, Decode, Debug, Clone)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
    pub currency_id: CurrencyId,
}

#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Clone, Debug)]
enum FundingRequestAccountType {
    User,
    Vault,
}

async fn _fund_account_raw(
    parachain_rpc: &InterBtcParachain,
    params: Params,
    store: Store,
    allowance_config: AllowanceConfig,
) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    fund_account(parachain_rpc, req, store, allowance_config).await
}

async fn get_account_type(
    parachain_rpc: &InterBtcParachain,
    account_id: AccountId,
) -> Result<FundingRequestAccountType, Error> {
    match parachain_rpc.get_vaults_by_account_id(&account_id).await {
        Ok(x) if !x.is_empty() => Ok(FundingRequestAccountType::Vault),
        _ => Ok(FundingRequestAccountType::User),
    }
}

fn open_kv_store<'a>(store: Store) -> Result<Bucket<'a, String, Json<FaucetRequest>>, Error> {
    Ok(store.bucket::<String, Json<FaucetRequest>>(Some(KV_STORE_NAME))?)
}

fn update_kv_store(
    kv: &Bucket<String, Json<FaucetRequest>>,
    account_id: String,
    request_timestamp: String,
    account_type: FundingRequestAccountType,
) -> Result<(), Error> {
    let faucet_request = FaucetRequest {
        datetime: request_timestamp,
        account_type,
    };
    kv.set(account_id, Json(faucet_request))?;
    Ok(())
}

fn is_type_and_was_user(
    account_type: FundingRequestAccountType,
    current_account_type: FundingRequestAccountType,
    previous_account_type: FundingRequestAccountType,
) -> bool {
    current_account_type.eq(&account_type) && previous_account_type.eq(&FundingRequestAccountType::User)
}

fn has_request_expired(
    request_datetime: DateTime<Utc>,
    cooldown_threshold: DateTime<Utc>,
    current_account_type: FundingRequestAccountType,
    previous_account_type: FundingRequestAccountType,
) -> bool {
    let cooldown_over = request_datetime.lt(&cooldown_threshold);

    // A user that has just become a vault or relayer can request again immediately
    cooldown_over
        || is_type_and_was_user(
            FundingRequestAccountType::Vault,
            current_account_type,
            previous_account_type,
        )
}

async fn ensure_funding_allowed(
    parachain_rpc: &InterBtcParachain,
    account_id: AccountId,
    allowance_config: AllowanceConfig,
    last_request_json: Option<Json<FaucetRequest>>,
    account_type: FundingRequestAccountType,
) -> Result<(), Error> {
    // Could get the currencies from either `user_allowances` or `vault_allowances`, assuming the same ones are used.
    let currency_ids: Result<Vec<_>, _> = allowance_config
        .user_allowances
        .iter()
        .map(|x| CurrencyId::try_from_symbol(x.symbol.clone()))
        .collect();
    for currency_id in currency_ids?.iter() {
        let free_balance = parachain_rpc
            .get_free_balance_for_id(account_id.clone(), *currency_id)
            .await?;
        let reserved_balance = parachain_rpc
            .get_reserved_balance_for_id(account_id.clone(), *currency_id)
            .await?;

        let one = |currency: CurrencyId| Ok::<_, Error>(10u128.pow(currency.decimals()? as u32));
        if free_balance + reserved_balance > allowance_config.max_fundable_client_balance * one(*currency_id)? {
            log::warn!(
                "User {} has enough {:?} funds: {:?}",
                account_id,
                currency_id,
                free_balance + reserved_balance
            );
            return Err(Error::AccountBalanceExceedsMaximum);
        }
    }

    // We are subtracting FAUCET_COOLDOWN_HOURS from the milliseconds since the unix epoch.
    // Unless there's a bug in the std lib implementation of Utc::now() or a false reading from the
    // system clock, the MathError will never occur
    let cooldown_threshold = Utc::now()
        .checked_sub_signed(ISO8601::hours(allowance_config.faucet_cooldown_hours))
        .ok_or(Error::MathError)?;

    match last_request_json {
        Some(last_request_json) => {
            let last_request_expired = has_request_expired(
                DateTime::parse_from_rfc2822(&last_request_json.0.datetime)?.with_timezone(&Utc),
                cooldown_threshold,
                account_type,
                last_request_json.0.account_type,
            );
            if !last_request_expired {
                log::warn!("Already funded {} at {:?}", account_id, last_request_json.0.datetime);
                Err(Error::AccountAlreadyFunded)
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

async fn atomic_faucet_funding(
    parachain_rpc: &InterBtcParachain,
    kv: Bucket<'_, String, Json<FaucetRequest>>,
    account_id: AccountId,
    allowance_config: AllowanceConfig,
) -> Result<(), Error> {
    let account_str = format!("{}", account_id);
    let last_request_json = kv.get(account_str.clone())?;
    let account_type = get_account_type(parachain_rpc, account_id.clone()).await?;
    let amounts: Allowance = match account_type {
        FundingRequestAccountType::User => allowance_config.user_allowances.clone(),
        FundingRequestAccountType::Vault => allowance_config.vault_allowances.clone(),
    };

    ensure_funding_allowed(
        parachain_rpc,
        account_id.clone(),
        allowance_config,
        last_request_json,
        account_type.clone(),
    )
    .await?;

    let mut transfers = vec![];
    for AllowanceAmount { symbol, amount } in amounts.iter() {
        let currency_id = CurrencyId::try_from_symbol(symbol.clone())?;
        log::info!(
            "AccountId: {}, Currency: {:?} Type: {:?}, Amount: {}",
            account_id,
            currency_id.symbol().unwrap_or_default(),
            account_type,
            amount
        );
        transfers.push(parachain_rpc.transfer_to(&account_id, *amount, currency_id));
    }

    let result = futures::future::join_all(transfers).await;

    if let Some(err) = result.into_iter().find_map(|x| x.err()) {
        return Err(err.into());
    }

    // Replace the previous (expired) claim datetime with the datetime of the current claim, only update
    // this after successfully transferring funds to ensure that this can be called again on error
    update_kv_store(&kv, account_str, Utc::now().to_rfc2822(), account_type.clone())?;
    Ok(())
}

async fn fund_account(
    parachain_rpc: &InterBtcParachain,
    req: FundAccountJsonRpcRequest,
    store: Store,
    allowance_config: AllowanceConfig,
) -> Result<(), Error> {
    let parachain_rpc = parachain_rpc.clone();
    let kv = open_kv_store(store)?;
    atomic_faucet_funding(&parachain_rpc, kv, req.account_id.clone(), allowance_config).await?;
    Ok(())
}

pub async fn start_http(
    parachain_rpc: InterBtcParachain,
    addr: SocketAddr,
    origin: String,
    allowance_config: AllowanceConfig,
) -> jsonrpc_http_server::CloseHandle {
    let mut io = IoHandler::default();
    let store = Store::new(Config::new("./kv")).expect("Unable to open kv store");
    let user_allowances_clone = allowance_config.user_allowances.clone();
    let vault_allowances_clone = allowance_config.vault_allowances.clone();
    io.add_sync_method("user_allowance", move |_| handle_resp(Ok(&user_allowances_clone)));
    io.add_sync_method("vault_allowance", move |_| handle_resp(Ok(&vault_allowances_clone)));
    {
        let parachain_rpc = parachain_rpc.clone();
        io.add_method("system_health", move |_| {
            let parachain_rpc = parachain_rpc.clone();
            async move { handle_resp(_system_health(&parachain_rpc).await) }
        });
    }
    {
        let parachain_rpc = parachain_rpc;
        let store = store;
        let allowance_config = allowance_config;

        // an async closure is only FnOnce, so we need this workaround
        io.add_method("fund_account", move |params| {
            let parachain_rpc = parachain_rpc.clone();
            let store = store.clone();
            let allowance_config = allowance_config.clone();
            async move {
                let result = _fund_account_raw(&parachain_rpc.clone(), params, store, allowance_config).await;
                if let Err(ref err) = result {
                    log::debug!("Failed to fund account: {}", err);
                }
                handle_resp(result)
            }
        });
    };

    let handle = tokio::runtime::Handle::current();
    let server = ServerBuilder::new(io)
        .event_loop_executor(handle)
        .health_api(("/health", "system_health"))
        .rest_api(jsonrpc_http_server::RestApi::Unsecure)
        .cors(DomainsValidation::AllowOnly(vec![origin.into()]))
        .start_http(&addr)
        .expect("Unable to start RPC server");

    let close_handle = server.close_handle();

    tokio::task::spawn_blocking(move || {
        log::info!("Starting http server...");
        server.wait();
    });

    close_handle
}

#[cfg(all(test, feature = "parachain-metadata-kintsugi-testnet"))]
mod tests {
    use crate::{error::Error, Allowance, AllowanceAmount, AllowanceConfig};
    use futures::{future::join_all, TryFutureExt};
    use runtime::{
        CurrencyId::{self},
        Error as RuntimeError, InterBtcParachain, OracleKey, RuntimeCurrencyInfo, Token, TryFromSymbol, VaultId, KBTC,
        KINT, KSM,
    };
    use std::sync::Arc;

    const DEFAULT_TESTING_CURRENCY: CurrencyId = Token(KSM);
    const DEFAULT_GOVERNANCE_CURRENCY: CurrencyId = Token(KINT);
    const DEFAULT_WRAPPED_CURRENCY: CurrencyId = Token(KBTC);

    use super::{fund_account, open_kv_store, CollateralBalancesPallet, FundAccountJsonRpcRequest};
    use kv::{Config, Store};
    use runtime::{
        integration::*, AccountId, BtcPublicKey, FixedPointNumber, FixedU128, OraclePallet, VaultRegistryPallet,
    };
    use sp_keyring::AccountKeyring;

    macro_rules! assert_err {
        ($result:expr, $err:pat) => {{
            match $result {
                Err($err) => (),
                Ok(v) => panic!("assertion failed: Ok({:?})", v),
                _ => panic!("expected: Err($err)"),
            }
        }};
    }

    fn dummy_public_key() -> BtcPublicKey {
        BtcPublicKey {
            0: [
                2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187, 55, 18, 45,
                222, 180, 119, 54, 243, 97, 173, 150, 161, 169, 230,
            ],
        }
    }

    async fn set_exchange_rate(client: SubxtClient) {
        let oracle_provider = setup_provider(client, AccountKeyring::Bob).await;
        let dot_key = OracleKey::ExchangeRate(DEFAULT_TESTING_CURRENCY);
        let exchange_rate = FixedU128::saturating_from_rational(1u128, 100u128);
        let ksm_key = OracleKey::ExchangeRate(Token(KBTC));

        oracle_provider
            .feed_values(vec![(dot_key, exchange_rate), (ksm_key, exchange_rate)])
            .await
            .expect("Unable to set exchange rate");
    }

    async fn get_multi_currency_balance(
        account_id: &AccountId,
        allowance_vec: &Vec<AllowanceAmount>,
        provider: &InterBtcParachain,
    ) -> Vec<(u128, CurrencyId)> {
        join_all(allowance_vec.iter().map(|x| {
            let currency_id = CurrencyId::try_from_symbol(x.symbol.clone()).unwrap();
            provider
                .get_free_balance_for_id(account_id.clone(), currency_id.clone())
                .map_ok(move |balance| (balance, currency_id.clone()))
        }))
        .await
        .into_iter()
        .map(|x| x.unwrap())
        .collect()
    }

    async fn drain_multi_currency(
        balance: &Vec<(u128, CurrencyId)>,
        provider: &InterBtcParachain,
        drain_account_id: &AccountId,
        leftover_units: u128,
    ) -> Result<(), RuntimeError> {
        join_all(balance.iter().map(|(amount, currency)| {
            let leftover = leftover_units * 10u128.pow(currency.decimals().unwrap());
            let amount_to_transfer = if *amount > leftover { amount - leftover } else { 0 };
            provider.transfer_to(&drain_account_id, amount_to_transfer, currency.clone())
        }))
        .await
        .into_iter()
        .collect()
    }

    fn assert_allowance_emitted(
        funds_before: &Vec<(u128, CurrencyId)>,
        funds_after: &Vec<(u128, CurrencyId)>,
        allowance_vec: &Vec<AllowanceAmount>,
    ) {
        for (i, funds_after) in funds_after.iter().enumerate() {
            let funds_before = *funds_before.get(i).unwrap();
            let allowance = allowance_vec.get(i).unwrap().clone();
            assert_eq!(funds_before.0 + allowance.amount, funds_after.0);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_user_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = [3; 32].into();
        let user_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 100),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
        ];
        let vault_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
        ];
        let allowance_config = AllowanceConfig::new(1000, 6, user_allowance.clone(), vault_allowance.clone());

        let store = Store::new(Config::new(tmp_dir.path().join("kv1"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = get_multi_currency_balance(&bob_account_id, &user_allowance, &alice_provider).await;

        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        fund_account(&Arc::from(alice_provider.clone()), req, store, allowance_config.clone())
            .await
            .expect("Funding the account failed");

        let bob_funds_after = get_multi_currency_balance(&bob_account_id, &user_allowance, &alice_provider).await;
        assert_allowance_emitted(&bob_funds_before, &bob_funds_after, &user_allowance);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_rich_user_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        // Bob's account is prefunded with lots of DOT
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 100),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
        ];
        let vault_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
        ];
        let allowance_config = AllowanceConfig::new(1000, 6, user_allowance.clone(), vault_allowance.clone());

        let store = Store::new(Config::new(tmp_dir.path().join("kv1"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        assert_err!(
            fund_account(&Arc::from(alice_provider.clone()), req, store, allowance_config).await,
            Error::AccountBalanceExceedsMaximum
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_user_immediately_after_registering_as_vault_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id = AccountKeyring::Bob.to_account_id();
        let bob_vault_id = VaultId::new(
            bob_account_id.clone(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let drain_account_id: AccountId = [3; 32].into();

        let user_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 3 * KSM.one()),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
        ];
        let vault_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
        ];
        let allowance_config = AllowanceConfig::new(1000, 6, user_allowance.clone(), vault_allowance.clone());

        let store = Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
        let bob_prefunded_amount = get_multi_currency_balance(&bob_account_id, &user_allowance, &bob_provider).await;
        drain_multi_currency(&bob_prefunded_amount, &bob_provider, &drain_account_id, 1)
            .await
            .expect("Unable to transfer funds");

        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };
        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowance_config.clone(),
        )
        .await
        .expect("Funding the account failed");

        bob_provider.register_public_key(dummy_public_key()).await.unwrap();
        bob_provider.register_vault(&bob_vault_id, 3 * KSM.one()).await.unwrap();

        let bob_funds_before = get_multi_currency_balance(&bob_account_id, &user_allowance, &alice_provider).await;
        fund_account(&Arc::from(alice_provider.clone()), req, store, allowance_config)
            .await
            .expect("Funding the account failed");
        let bob_funds_after = get_multi_currency_balance(&bob_account_id, &user_allowance, &alice_provider).await;
        assert_allowance_emitted(&bob_funds_before, &bob_funds_after, &vault_allowance);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_user_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = [3; 32].into();
        let user_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 100),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
        ];
        let vault_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
        ];
        let allowance_config = AllowanceConfig::new(1000, 6, user_allowance, vault_allowance);

        let store = Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowance_config.clone(),
        )
        .await
        .expect("Funding the account failed");

        assert_err!(
            fund_account(&Arc::from(alice_provider.clone()), req, store, allowance_config).await,
            Error::AccountAlreadyFunded
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_vault_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let store = Store::new(Config::new(tmp_dir.path().join("kv4"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();

        for currency_id in [Token(KINT), Token(KSM)] {
            kv.clear().unwrap();
            let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
            let bob_vault_id = VaultId::new(bob_account_id.clone(), currency_id, DEFAULT_WRAPPED_CURRENCY);
            let drain_account_id: AccountId = [3; 32].into();

            let user_allowance: Allowance = vec![
                AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 100),
                AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
            ];
            let vault_allowance: Allowance = vec![
                AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
                AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
            ];
            let allowance_config = AllowanceConfig::new(1000, 6, user_allowance.clone(), vault_allowance.clone());

            let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
            if bob_provider.get_public_key().await.unwrap().is_none() {
                bob_provider.register_public_key(dummy_public_key()).await.unwrap();
            }
            let one_unit = 10u128.pow(currency_id.decimals().unwrap());
            bob_provider.register_vault(&bob_vault_id, 55 * one_unit).await.unwrap();

            let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

            // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
            let bob_prefunded_amount =
                get_multi_currency_balance(&bob_account_id, &user_allowance, &bob_provider).await;
            drain_multi_currency(&bob_prefunded_amount, &bob_provider, &drain_account_id, 55)
                .await
                .expect("Unable to transfer funds");

            let bob_funds_before = get_multi_currency_balance(&bob_account_id, &user_allowance, &bob_provider).await;
            let req = FundAccountJsonRpcRequest {
                account_id: bob_account_id.clone(),
                currency_id,
            };

            fund_account(&Arc::from(alice_provider.clone()), req, store.clone(), allowance_config)
                .await
                .expect("Funding the account failed");

            let bob_funds_after = get_multi_currency_balance(&bob_account_id, &user_allowance, &bob_provider).await;
            assert_allowance_emitted(&bob_funds_before, &bob_funds_after, &vault_allowance);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fund_vault_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let bob_vault_id = VaultId::new(
            bob_account_id.clone(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let drain_account_id: AccountId = [3; 32].into();

        let user_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 100),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 100),
        ];
        let vault_allowance: Allowance = vec![
            AllowanceAmount::new(DEFAULT_TESTING_CURRENCY.symbol().unwrap(), 200),
            AllowanceAmount::new(DEFAULT_GOVERNANCE_CURRENCY.symbol().unwrap(), 200),
        ];
        let allowance_config = AllowanceConfig::new(1000, 6, user_allowance.clone(), vault_allowance.clone());

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider.register_public_key(dummy_public_key()).await.unwrap();
        bob_provider.register_vault(&bob_vault_id, 3 * KSM.one()).await.unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
        let bob_prefunded_amount = get_multi_currency_balance(&bob_account_id, &user_allowance, &bob_provider).await;
        drain_multi_currency(&bob_prefunded_amount, &bob_provider, &drain_account_id, 1)
            .await
            .expect("Unable to transfer funds");

        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        let store = Store::new(Config::new(tmp_dir.path().join("kv5"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();
        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowance_config.clone(),
        )
        .await
        .expect("Funding the account failed");

        assert_err!(
            fund_account(&Arc::from(alice_provider.clone()), req, store, allowance_config).await,
            Error::AccountAlreadyFunded
        );
    }
}
