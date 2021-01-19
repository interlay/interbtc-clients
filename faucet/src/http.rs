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
    AccountId, DotBalancesPallet, PolkaBtcProvider, SecurityPallet, VaultRegistryPallet,
};
use serde::{Deserialize, Deserializer};
use std::net::SocketAddr;
use std::sync::Arc;

const KV_STORE_NAME: &str = "store";
const FAUCET_COOLDOWN_HOURS: i64 = 6;
const DOT_TO_PLANCK: u128 = 10000000000;

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

fn _system_health(api: &Arc<PolkaBtcProvider>) -> Result<(), Error> {
    block_on(api.get_parachain_status())?;
    Ok(())
}

#[derive(Encode, Decode, Debug, Clone)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
}

async fn _fund_account_raw(
    api: &Arc<PolkaBtcProvider>,
    params: Params,
    store: Store,
    user_allowance: u128,
    vault_allowance: u128,
) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    fund_account(api, req, store, user_allowance, vault_allowance).await
}

async fn get_faucet_amount(
    provider: &Arc<PolkaBtcProvider>,
    id: AccountId,
    user_allowance_dot: u128,
    vault_allowance_dot: u128,
) -> Result<u128, Error> {
    let req_vault = provider.get_vault(id.clone()).await;
    let vault_allowance_planck = vault_allowance_dot
        .checked_mul(DOT_TO_PLANCK)
        .ok_or(Error::MathError)?;
    let user_allowance_planck = user_allowance_dot
        .checked_mul(DOT_TO_PLANCK)
        .ok_or(Error::MathError)?;
    match req_vault {
        Ok(_) => Ok(vault_allowance_planck),
        Err(_) => Ok(user_allowance_planck),
    }
}

fn open_kv_store<'a>(store: Store) -> Result<Bucket<'a, String, String>, Error> {
    Ok(store.bucket::<String, String>(Some(KV_STORE_NAME))?)
}

fn update_kv_store(
    kv: &Bucket<String, String>,
    account_id: AccountId,
    request_timestamp: String,
) -> Result<(), Error> {
    kv.set(account_id.to_string(), request_timestamp)?;
    kv.flush()?;
    Ok(())
}

fn has_request_expired(last_claim_time: Option<String>) -> Result<bool, Error> {
    // We are subtracting FAUCET_COOLDOWN_HOURS from the milliseconds since the unix epoch.
    // Unless there's a bug in the std lib implementation of Utc::now() or a false reading from the
    // system clock, unwrap will never panic
    let filter_datetime = Utc::now()
        .checked_sub_signed(Duration::hours(FAUCET_COOLDOWN_HOURS))
        .ok_or(Error::MathError)?;
    Ok(match last_claim_time {
        Some(datetime) => DateTime::parse_from_rfc2822(&datetime)?.lt(&filter_datetime),
        None => true,
    })
}

async fn atomic_faucet_funding(
    provider: &Arc<PolkaBtcProvider>,
    kv: Bucket<'_, String, String>,
    account_id: AccountId,
    user_allowance: u128,
    vault_allowance: u128,
) -> Result<(), Error> {
    let last_claim_time = kv.get(account_id.to_string())?;
    if !has_request_expired(last_claim_time)? {
        return Err(Error::FaucetOveruseError);
    }
    // Replace the previous, expired claim datetime with the datetime of the current claim
    update_kv_store(&kv, account_id.clone(), Utc::now().to_rfc2822())?;
    let amount = get_faucet_amount(
        &provider,
        account_id.clone(),
        user_allowance,
        vault_allowance,
    )
    .await?;
    provider.transfer_to(account_id, amount).await?;
    Ok(())
}

async fn fund_account(
    api: &Arc<PolkaBtcProvider>,
    req: FundAccountJsonRpcRequest,
    store: Store,
    user_allowance: u128,
    vault_allowance: u128,
) -> Result<(), Error> {
    let provider = api.clone();
    let kv = open_kv_store(store)?;
    block_on(atomic_faucet_funding(
        &provider,
        kv,
        req.account_id.clone(),
        user_allowance,
        vault_allowance,
    ))?;
    Ok(())
}

pub async fn start(
    api: Arc<PolkaBtcProvider>,
    addr: SocketAddr,
    origin: String,
    user_allowance: u128,
    vault_allowance: u128,
) {
    let mut io = IoHandler::default();
    let api = api.clone();
    {
        let api = api.clone();
        io.add_sync_method("system_health", move |_| handle_resp(_system_health(&api)));
    }
    {
        let api = api.clone();

        // an async closure is only FnOnce, so we need this workaround
        io.add_method("fund_account", move |params| {
            let api = api.clone();
            async move {
                let store = Store::new(Config::new("./kv")).expect("Unable to open kv store");
                let result =
                    _fund_account_raw(&api.clone(), params, store, user_allowance, vault_allowance)
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
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use kv::{Config, Store};
    use runtime::{AccountId, BtcPublicKey, PolkaBtcRuntime, VaultRegistryPallet};

    use super::{
        fund_account, open_kv_store, update_kv_store, DotBalancesPallet, FundAccountJsonRpcRequest,
        PolkaBtcProvider, DOT_TO_PLANCK,
    };
    use jsonrpsee::Client as JsonRpseeClient;
    use runtime::substrate_subxt::PairSigner;
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
            db: DatabaseConfig::RocksDb {
                path: tmp.path().join("db"),
                cache_size: 128,
            },
            keystore: KeystoreConfig::Path {
                path: tmp.path().join("keystore"),
                password: None,
            },
            chain_spec: btc_parachain::chain_spec::development_config(true).unwrap(),
            role: Role::Authority(key.clone()),
            telemetry: None,
        };

        let client = SubxtClient::from_config(config, btc_parachain::service::new_full)
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
        dot.checked_mul(DOT_TO_PLANCK).unwrap()
    }

    #[tokio::test]
    async fn test_fund_user_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
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

        fund_account(
            &Arc::from(alice_provider.clone()),
            req,
            store,
            user_allowance_dot,
            vault_allowance_dot,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_user_after_cooldown_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
        let expected_amount_planck: u128 = dot_to_planck(user_allowance_dot);

        let store =
            Store::new(Config::new(tmp_dir.path().join("kv2"))).expect("Unable to open kv store");
        let kv = open_kv_store(store.clone()).unwrap();
        kv.clear().unwrap();

        // Add a request older than the cooldown length to kv store, so it will be filtered out
        let filter_datetime = Utc::now().checked_sub_signed(Duration::hours(7)).unwrap();
        update_kv_store(&kv, bob_account_id.clone(), filter_datetime.to_rfc2822()).unwrap();

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
            req,
            store,
            user_allowance_dot,
            vault_allowance_dot,
        )
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
            user_allowance_dot,
            vault_allowance_dot,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();
        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store,
                user_allowance_dot,
                vault_allowance_dot,
            )
            .await,
            Error::FaucetOveruseError
        );
    }

    #[tokio::test]
    async fn test_fund_vault_once_succeeds() {
        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let user_allowance_dot: u128 = 1;
        let vault_allowance_dot: u128 = 500;
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
        fund_account(
            &Arc::from(alice_provider.clone()),
            req,
            store,
            user_allowance_dot,
            vault_allowance_dot,
        )
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
            user_allowance_dot,
            vault_allowance_dot,
        )
        .await
        .expect("Funding the account failed");

        let bob_funds_after = alice_provider
            .get_free_dot_balance_for_id(bob_account_id)
            .await
            .unwrap();

        assert_eq!(bob_funds_before + expected_amount_planck, bob_funds_after);

        assert_err!(
            fund_account(
                &Arc::from(alice_provider.clone()),
                req,
                store,
                user_allowance_dot,
                vault_allowance_dot,
            )
            .await,
            Error::FaucetOveruseError
        );
    }
}
