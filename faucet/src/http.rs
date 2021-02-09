use crate::Error;
use chrono::{DateTime, Duration, Utc};
use futures::{self, executor::block_on};
use hex::FromHex;
use jsonrpc_http_server::jsonrpc_core::serde_json::Value;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use kv::*;
use log::error;
use parity_scale_codec::{Decode, Encode};
use runtime::{
    AccountId, DotBalancesPallet, PolkaBtcProvider, SecurityPallet, StakedRelayerPallet,
    VaultRegistryPallet, PLANCK_PER_DOT,
};
use serde::{Deserialize, Deserializer};
use std::sync::Arc;
use std::{collections::HashMap, net::SocketAddr};

const KV_STORE_NAME: &str = "store";
const FAUCET_COOLDOWN_HOURS: i64 = 6;

#[derive(serde::Serialize, serde::Deserialize, PartialEq)]
struct FaucetRequest {
    datetime: String,
    account_type: FundingRequestAccountType,
}

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(err) => {
            error!("Error: {}", err.to_string());
            Err(JsonRpcError::invalid_request())
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawBytes(#[serde(deserialize_with = "hex_to_buffer")] Vec<u8>);

pub fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        Vec::from_hex(&string[2..]).map_err(|err| Error::custom(err.to_string()))
    })
}

fn _system_health(provider: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    block_on(provider.get_parachain_status())?;
    Ok(())
}

#[derive(Encode, Decode, Debug, Clone)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
}

#[derive(PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Clone, Debug)]
enum FundingRequestAccountType {
    User,
    Vault,
    StakedRelayer,
}

async fn _fund_account_raw(
    provider: &Arc<PolkaBtcProvider>,
    params: Params,
    store: Store,
    user_allowance: u128,
    vault_allowance: u128,
    staked_relayer_allowance: u128,
) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    let mut allowances = HashMap::new();
    allowances.insert(FundingRequestAccountType::User, user_allowance);
    allowances.insert(FundingRequestAccountType::Vault, vault_allowance);
    allowances.insert(
        FundingRequestAccountType::StakedRelayer,
        staked_relayer_allowance,
    );
    fund_account(provider, req, store, allowances).await
}

async fn get_account_type(
    provider: &Arc<PolkaBtcProvider>,
    account_id: AccountId,
) -> Result<FundingRequestAccountType, Error> {
    if let Ok(_) = provider.get_vault(account_id.clone()).await {
        return Ok(FundingRequestAccountType::Vault);
    }
    let active_stake = provider.get_stake_by_id(account_id.clone()).await?;
    let inactive_stake = provider.get_inactive_stake_by_id(account_id).await?;
    if active_stake.gt(&0) || inactive_stake.gt(&0) {
        return Ok(FundingRequestAccountType::StakedRelayer);
    }
    Ok(FundingRequestAccountType::User)
}

fn open_kv_store<'a>(store: Store) -> Result<Bucket<'a, String, Json<FaucetRequest>>, Error> {
    Ok(store.bucket::<String, Json<FaucetRequest>>(Some(KV_STORE_NAME))?)
}

fn update_kv_store(
    kv: &Bucket<String, Json<FaucetRequest>>,
    account_id: AccountId,
    request_timestamp: String,
    account_type: FundingRequestAccountType,
) -> Result<(), Error> {
    let faucet_request = FaucetRequest {
        datetime: request_timestamp,
        account_type,
    };
    kv.set(account_id.to_string(), Json(faucet_request))?;
    kv.flush()?;
    Ok(())
}

fn is_type_and_was_user(
    account_type: FundingRequestAccountType,
    current_account_type: FundingRequestAccountType,
    previous_account_type: FundingRequestAccountType,
) -> bool {
    current_account_type.eq(&account_type)
        && previous_account_type.eq(&FundingRequestAccountType::User)
}

fn has_request_expired(
    request_datetime: DateTime<Utc>,
    cooldown_threshold: DateTime<Utc>,
    current_account_type: FundingRequestAccountType,
    previous_account_type: FundingRequestAccountType,
) -> bool {
    let cooldown_over = request_datetime.lt(&cooldown_threshold);

    // A user that has just become a vault can request again immediately
    return cooldown_over
        || is_type_and_was_user(
            FundingRequestAccountType::Vault,
            current_account_type.clone(),
            previous_account_type.clone(),
        )
        || is_type_and_was_user(
            FundingRequestAccountType::StakedRelayer,
            current_account_type,
            previous_account_type,
        );
}

fn is_funding_allowed(
    last_request_json: Option<Json<FaucetRequest>>,
    account_type: FundingRequestAccountType,
) -> Result<bool, Error> {
    // We are subtracting FAUCET_COOLDOWN_HOURS from the milliseconds since the unix epoch.
    // Unless there's a bug in the std lib implementation of Utc::now() or a false reading from the
    // system clock, unwrap will never panic
    let cooldown_threshold = Utc::now()
        .checked_sub_signed(Duration::hours(FAUCET_COOLDOWN_HOURS))
        .ok_or(Error::MathError)?;

    Ok(match last_request_json {
        Some(last_request_json) => has_request_expired(
            DateTime::parse_from_rfc2822(&last_request_json.0.datetime)?.with_timezone(&Utc),
            cooldown_threshold,
            account_type,
            last_request_json.0.account_type,
        ),
        None => true,
    })
}

async fn atomic_faucet_funding(
    provider: &Arc<PolkaBtcProvider>,
    kv: Bucket<'_, String, Json<FaucetRequest>>,
    account_id: AccountId,
    allowances: HashMap<FundingRequestAccountType, u128>,
) -> Result<(), Error> {
    let last_request_json = kv.get(account_id.to_string())?;
    let account_type = get_account_type(&provider, account_id.clone()).await?;
    if !is_funding_allowed(last_request_json, account_type.clone())? {
        return Err(Error::FaucetOveruseError);
    }
    // Replace the previous, expired claim datetime with the datetime of the current claim
    update_kv_store(
        &kv,
        account_id.clone(),
        Utc::now().to_rfc2822(),
        account_type.clone(),
    )?;
    let amount = allowances
        .get(&account_type)
        .ok_or(Error::NoFaucetAllowance)?
        .checked_mul(PLANCK_PER_DOT)
        .ok_or(Error::MathError)?;
    provider.transfer_to(account_id, amount).await?;
    Ok(())
}

async fn fund_account(
    provider: &Arc<PolkaBtcProvider>,
    req: FundAccountJsonRpcRequest,
    store: Store,
    allowances: HashMap<FundingRequestAccountType, u128>,
) -> Result<(), Error> {
    let provider = provider.clone();
    let kv = open_kv_store(store)?;
    block_on(atomic_faucet_funding(
        &provider,
        kv,
        req.account_id.clone(),
        allowances,
    ))?;
    Ok(())
}

pub async fn start(
    provider: Arc<PolkaBtcProvider>,
    addr: SocketAddr,
    origin: String,
    user_allowance: u128,
    vault_allowance: u128,
    staked_relayer_allowance: u128,
) {
    let mut io = IoHandler::default();
    io.add_sync_method("user_allowance", move |_| handle_resp(Ok(user_allowance)));
    io.add_sync_method("vault_allowance", move |_| handle_resp(Ok(vault_allowance)));
    io.add_sync_method("staked_relayer_allowance", move |_| {
        handle_resp(Ok(staked_relayer_allowance))
    });
    let provider = provider.clone();
    {
        let provider = provider.clone();
        io.add_sync_method("system_health", move |_| {
            handle_resp(_system_health(&provider))
        });
    }
    {
        let provider = provider.clone();

        // an async closure is only FnOnce, so we need this workaround
        io.add_method("fund_account", move |params| {
            let provider = provider.clone();
            async move {
                let store = Store::new(Config::new("./kv")).expect("Unable to open kv store");
                let result = _fund_account_raw(
                    &provider.clone(),
                    params,
                    store,
                    user_allowance,
                    vault_allowance,
                    staked_relayer_allowance,
                )
                .await;
                handle_resp(result)
            }
        });
    };

    let server = ServerBuilder::new(io)
        .health_api(("/health", "system_health"))
        .rest_api(jsonrpc_http_server::RestApi::Unsecure)
        .cors(DomainsValidation::AllowOnly(vec![origin.into()]))
        .start_http(&addr)
        .expect("Unable to start RPC server");

    tokio::task::spawn_blocking(move || {
        server.wait();
    })
    .await
    .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::Error;
    use std::{collections::HashMap, sync::Arc};

    use super::{
        fund_account, open_kv_store, DotBalancesPallet, FundAccountJsonRpcRequest,
        FundingRequestAccountType, PolkaBtcProvider, PLANCK_PER_DOT,
    };
    use jsonrpsee::Client as JsonRpseeClient;
    use kv::{Config, Store};
    use runtime::{substrate_subxt::PairSigner, StakedRelayerPallet};
    use runtime::{AccountId, BtcPublicKey, PolkaBtcRuntime, VaultRegistryPallet};
    use sp_keyring::AccountKeyring;
    use substrate_subxt_client::{
        DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
    };
    use tempdir::TempDir;

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
        BtcPublicKey([
            2, 205, 114, 218, 156, 16, 235, 172, 106, 37, 18, 153, 202, 140, 176, 91, 207, 51, 187,
            55, 18, 45, 222, 180, 119, 54, 243, 97, 173, 150, 161, 169, 230,
        ])
    }

    async fn default_provider_client(key: AccountKeyring) -> (JsonRpseeClient, TempDir) {
        let tmp = TempDir::new("btc-parachain-").expect("failed to create tempdir");
        let config = SubxtClientConfig {
            impl_name: "btc-parachain-full-client",
            impl_version: "0.0.1",
            author: "Interlay Ltd",
            copyright_start_year: 2020,
            db: DatabaseConfig::ParityDb {
                path: tmp.path().join("db"),
            },
            keystore: KeystoreConfig::Path {
                path: tmp.path().join("keystore"),
                password: None,
            },
            chain_spec: btc_parachain::chain_spec::development_config(),
            role: Role::Authority(key.clone()),
            telemetry: None,
        };

        let client = SubxtClient::from_config(config, btc_parachain_service::new_full)
            .expect("Error creating subxt client")
            .into();
        return (client, tmp);
    }

    async fn setup_provider(client: JsonRpseeClient, key: AccountKeyring) -> PolkaBtcProvider {
        let signer = PairSigner::<PolkaBtcRuntime, _>::new(key.pair());
        PolkaBtcProvider::new(client, signer)
            .await
            .expect("Error creating provider")
    }

    fn dot_to_planck(dot: u128) -> u128 {
        dot.checked_mul(PLANCK_PER_DOT).unwrap()
    }

    #[tokio::test]
    async fn test_fund_user_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );

        let expected_amount_planck: u128 = dot_to_planck(user_allowance_dot);

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv1"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        fund_account(&Arc::from(alice_provider.clone()), req, store, allowances)
            .await
            .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_user_immediately_after_registering_as_vault_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );
        let expected_amount_planck: u128 = dot_to_planck(vault_allowance_dot);

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowances.clone(),
        )
        .await
        .expect("Funding the account failed");

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider
            .register_vault(100, dummy_public_key())
            .await
            .unwrap();

        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();

        fund_account(&Arc::from(alice_provider.clone()), req, store, allowances)
            .await
            .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_user_immediately_after_registering_as_staked_relayer_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );
        let expected_amount_planck: u128 = dot_to_planck(staked_relayer_allowance_dot);

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;

        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowances.clone(),
        )
        .await
        .expect("Funding the account failed");

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider.register_staked_relayer(100).await.unwrap();

        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();

        fund_account(&Arc::from(alice_provider.clone()), req, store, allowances)
            .await
            .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_user_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );
        let expected_amount_planck: u128 = dot_to_planck(user_allowance_dot);

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv3"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowances.clone(),
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(&Arc::from(alice_provider.clone()), req, store, allowances).await,
            Error::FaucetOveruseError
        );
    }

    #[tokio::test]
    async fn test_fund_vault_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );
        let expected_amount_planck: u128 = dot_to_planck(vault_allowance_dot);

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider
            .register_vault(100, dummy_public_key())
            .await
            .unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv4"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();
        fund_account(&Arc::from(alice_provider.clone()), req, store, allowances)
            .await
            .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_vault_twice_in_a_row_fails() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let staked_relayer_allowance_dot: u128 = 500;

        let mut allowances: HashMap<FundingRequestAccountType, u128> = HashMap::new();
        allowances.insert(FundingRequestAccountType::User, user_allowance_dot);
        allowances.insert(FundingRequestAccountType::Vault, vault_allowance_dot);
        allowances.insert(
            FundingRequestAccountType::StakedRelayer,
            staked_relayer_allowance_dot,
        );
        let expected_amount_planck: u128 = dot_to_planck(vault_allowance_dot);

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        bob_provider
            .register_vault(100, dummy_public_key())
            .await
            .unwrap();

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let bob_funds_before = alice_provider
            .get_free_dot_balance_for_id(bob_account_id.clone())
            .await
            .unwrap();
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
        };

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv5"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();
        fund_account(
            &Arc::from(alice_provider.clone()),
            req.clone(),
            store.clone(),
            allowances.clone(),
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(&Arc::from(alice_provider.clone()), req, store, allowances).await,
            Error::FaucetOveruseError
        );
    }
}
