use crate::error::Error;
use chrono::{DateTime, Duration as ISO8601, Utc};
use hex::FromHex;
use jsonrpc_http_server::{
    jsonrpc_core::{serde_json::Value, Error as JsonRpcError, ErrorCode as JsonRpcErrorCode, IoHandler, Params},
    DomainsValidation, ServerBuilder,
};
use kv::*;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    AccountId, CollateralBalancesPallet, CurrencyId, CurrencyIdExt, CurrencyInfo, Error as RuntimeError,
    InterBtcParachain, VaultRegistryPallet,
};
use serde::{Deserialize, Deserializer};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use tokio::time::timeout;

const HEALTH_DURATION: Duration = Duration::from_millis(5000);

const KV_STORE_NAME: &str = "store";
const FAUCET_COOLDOWN_HOURS: i64 = 6;

// If the client has more 50 DOT it won't be funded
const MAX_FUNDABLE_CLIENT_BALANCE: u128 = 500_000_000_000;

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
    match timeout(HEALTH_DURATION, parachain_rpc.get_latest_block_hash()).await {
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
    user_allowance: u128,
    vault_allowance: u128,
    native_currency_id: CurrencyId,
) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    let mut allowances = HashMap::new();
    allowances.insert(FundingRequestAccountType::User, user_allowance);
    allowances.insert(FundingRequestAccountType::Vault, vault_allowance);
    fund_account(parachain_rpc, req, store, allowances, native_currency_id).await
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
    currency_id: CurrencyId,
    last_request_json: Option<Json<FaucetRequest>>,
    account_type: FundingRequestAccountType,
) -> Result<(), Error> {
    let free_balance = parachain_rpc
        .get_free_balance_for_id(account_id.clone(), currency_id)
        .await?;
    let reserved_balance = parachain_rpc
        .get_reserved_balance_for_id(account_id.clone(), currency_id)
        .await?;
    if free_balance + reserved_balance > MAX_FUNDABLE_CLIENT_BALANCE {
        log::warn!(
            "User {} has enough funds: {:?}",
            account_id,
            free_balance + reserved_balance
        );
        return Err(Error::AccountBalanceExceedsMaximum);
    }

    // We are subtracting FAUCET_COOLDOWN_HOURS from the milliseconds since the unix epoch.
    // Unless there's a bug in the std lib implementation of Utc::now() or a false reading from the
    // system clock, the MathError will never occur
    let cooldown_threshold = Utc::now()
        .checked_sub_signed(ISO8601::hours(FAUCET_COOLDOWN_HOURS))
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
    currency_id: CurrencyId,
    native_currency_id: CurrencyId,
    allowances: HashMap<FundingRequestAccountType, u128>,
) -> Result<(), Error> {
    let account_str = format!("{}-{}", account_id, currency_id.inner().symbol());
    let last_request_json = kv.get(account_str.clone())?;
    let account_type = get_account_type(parachain_rpc, account_id.clone()).await?;
    ensure_funding_allowed(
        parachain_rpc,
        account_id.clone(),
        currency_id,
        last_request_json,
        account_type.clone(),
    )
    .await?;

    let amount = allowances
        .get(&account_type)
        .ok_or(Error::NoFaucetAllowance)?
        .checked_mul(currency_id.inner().one())
        .ok_or(Error::MathError)?;

    log::info!(
        "AccountId: {}, Currency: {:?} Type: {:?}, Amount: {}",
        account_id,
        currency_id.inner().symbol(),
        account_type,
        amount
    );

    let mut transfers = vec![parachain_rpc.transfer_to(&account_id, amount, currency_id)];
    if currency_id != native_currency_id {
        transfers.push(parachain_rpc.transfer_to(&account_id, amount, native_currency_id));
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
    allowances: HashMap<FundingRequestAccountType, u128>,
    native_currency_id: CurrencyId,
) -> Result<(), Error> {
    let parachain_rpc = parachain_rpc.clone();
    let kv = open_kv_store(store)?;
    atomic_faucet_funding(
        &parachain_rpc,
        kv,
        req.account_id.clone(),
        req.currency_id,
        native_currency_id,
        allowances,
    )
    .await?;
    Ok(())
}

pub async fn start_http(
    parachain_rpc: InterBtcParachain,
    addr: SocketAddr,
    origin: String,
    user_allowance: u128,
    vault_allowance: u128,
    native_currency_id: CurrencyId,
) -> jsonrpc_http_server::CloseHandle {
    let mut io = IoHandler::default();
    let store = Store::new(Config::new("./kv")).expect("Unable to open kv store");
    io.add_sync_method("user_allowance", move |_| handle_resp(Ok(user_allowance)));
    io.add_sync_method("vault_allowance", move |_| handle_resp(Ok(vault_allowance)));
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

        // an async closure is only FnOnce, so we need this workaround
        io.add_method("fund_account", move |params| {
            let parachain_rpc = parachain_rpc.clone();
            let store = store.clone();
            async move {
                let result = _fund_account_raw(
                    &parachain_rpc.clone(),
                    params,
                    store,
                    user_allowance,
                    vault_allowance,
                    native_currency_id,
                )
                .await;
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

#[cfg(all(test, feature = "standalone-metadata"))]
mod tests {
    use crate::error::Error;
    use runtime::{CurrencyId, CurrencyIdExt, OracleKey, Token, VaultId, DOT, INTERBTC, INTR, KBTC, KSM};
    use std::{collections::HashMap, sync::Arc};

    const DEFAULT_TESTING_CURRENCY: CurrencyId = Token(DOT);
    const DEFAULT_WRAPPED_CURRENCY: CurrencyId = Token(INTERBTC);
    const DEFAULT_NATIVE_CURRENCY: CurrencyId = Token(INTR);

    use super::{
        fund_account, open_kv_store, CollateralBalancesPallet, FundAccountJsonRpcRequest, FundingRequestAccountType,
    };
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

    #[tokio::test]
    async fn test_fund_user_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = [3; 32].into();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        let testing_currency: CurrencyId = DEFAULT_TESTING_CURRENCY.into();
        let expected_amount_planck: u128 = user_allowance_dot * testing_currency.inner().one();

        let store = Store::new(Config::new(tmp_dir.path().join("kv1"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req,
            store,
            allowances,
            DEFAULT_NATIVE_CURRENCY,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_balance_for_id(bob_account_id, DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_rich_user_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        // Bob's account is prefunded with lots of DOT
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);

        let store = Store::new(Config::new(tmp_dir.path().join("kv1"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        assert_err!(
            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store,
                allowances,
                DEFAULT_NATIVE_CURRENCY
            )
            .await,
            Error::AccountBalanceExceedsMaximum
        );
    }

    #[tokio::test]
    async fn test_fund_user_immediately_after_registering_as_vault_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id = AccountKeyring::Bob.to_account_id();
        let bob_vault_id = VaultId::new(
            bob_account_id.clone(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let one_dot: u128 = 10u128.pow(10);
        let drain_account_id: AccountId = [3; 32].into();

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        let testing_currency: CurrencyId = DEFAULT_TESTING_CURRENCY.into();
        let expected_amount_planck: u128 = vault_allowance_dot * testing_currency.inner().one();

        let store = Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
        let bob_prefunded_amount = bob_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        bob_provider
            .transfer_to(
                &drain_account_id,
                bob_prefunded_amount - one_dot,
                DEFAULT_TESTING_CURRENCY,
            )
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
            allowances.clone(),
            DEFAULT_NATIVE_CURRENCY,
        )
        .await
        .expect("Funding the account failed");

        bob_provider
            .register_vault(&bob_vault_id, 100, dummy_public_key())
            .await
            .unwrap();

        let bob_funds_before = alice_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();

        fund_account(
            &Arc::from(alice_provider.clone()),
            req,
            store,
            allowances,
            DEFAULT_NATIVE_CURRENCY,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_balance_for_id(bob_account_id, DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_user_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = [3; 32].into();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        let testing_currency: CurrencyId = DEFAULT_TESTING_CURRENCY.into();
        let expected_amount_planck: u128 = user_allowance_dot * testing_currency.inner().one();

        let store = Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            currency_id: DEFAULT_TESTING_CURRENCY,
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowances.clone(),
            DEFAULT_NATIVE_CURRENCY,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_balance_for_id(bob_account_id, DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store,
                allowances,
                DEFAULT_NATIVE_CURRENCY
            )
            .await,
            Error::AccountAlreadyFunded
        );
    }

    #[tokio::test]
    async fn test_fund_vault_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let store = Store::new(Config::new(tmp_dir.path().join("kv4"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        for currency_id in [Token(DOT), Token(KSM)] {
            let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
            let bob_vault_id = VaultId::new(bob_account_id.clone(), currency_id, DEFAULT_WRAPPED_CURRENCY);
            let user_allowance_dot: u128 = 1;
            let vault_allowance_dot: u128 = 500;
            let one_dot: u128 = 10u128.pow(10);
            let drain_account_id: AccountId = [3; 32].into();

            let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
            allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
            allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
            let rich_currency_id: CurrencyId = currency_id.into();
            let expected_amount_planck: u128 = vault_allowance_dot * rich_currency_id.inner().one();

            let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
            bob_provider
                .register_vault(&bob_vault_id, 100, dummy_public_key())
                .await
                .unwrap();

            let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

            // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
            let bob_prefunded_amount = bob_provider
                .get_free_balance_for_id(bob_account_id.clone(), currency_id)
                .await
                .unwrap();
            bob_provider
                .transfer_to(&drain_account_id, bob_prefunded_amount - one_dot, currency_id)
                .await
                .expect("Unable to transfer funds");

            let bob_funds_before = bob_provider
                .get_free_balance_for_id(bob_account_id.clone(), currency_id)
                .await
                .unwrap();
            let req = FundAccountJsonRpcRequest {
                account_id: bob_account_id.clone(),
                currency_id,
            };

            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store.clone(),
                allowances,
                DEFAULT_NATIVE_CURRENCY,
            )
            .await
            .expect("Funding the account failed");

            let bob_funds_after = alice_provider
                .get_free_balance_for_id(bob_account_id, currency_id)
                .await
                .unwrap();

            assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
        }
    }

    #[tokio::test]
    async fn test_fund_vault_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        set_exchange_rate(client.clone()).await;

        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let bob_vault_id = VaultId::new(
            bob_account_id.clone(),
            DEFAULT_TESTING_CURRENCY,
            DEFAULT_WRAPPED_CURRENCY,
        );
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let one_dot: u128 = 10u128.pow(10);
        let drain_account_id: AccountId = [3; 32].into();

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        let testing_currency: CurrencyId = DEFAULT_TESTING_CURRENCY.into();
        let expected_amount_planck: u128 = vault_allowance_dot * testing_currency.inner().one();

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider
            .register_vault(&bob_vault_id, 100, dummy_public_key())
            .await
            .unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        // Drain the amount Bob was prefunded by, so he is eligible to receive Faucet funding
        let bob_prefunded_amount = bob_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
        bob_provider
            .transfer_to(
                &drain_account_id,
                bob_prefunded_amount - one_dot,
                DEFAULT_TESTING_CURRENCY,
            )
            .await
            .expect("Unable to transfer funds");

        let bob_funds_before = alice_provider
            .get_free_balance_for_id(bob_account_id.clone(), DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();
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
            allowances.clone(),
            DEFAULT_NATIVE_CURRENCY,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_balance_for_id(bob_account_id, DEFAULT_TESTING_CURRENCY)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store,
                allowances,
                DEFAULT_NATIVE_CURRENCY
            )
            .await,
            Error::AccountBalanceExceedsMaximum
        );
    }
}
