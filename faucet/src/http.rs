use crate::Error;
use env_logger::fmt::Timestamp;
use futures::{self, future, Future, executor::block_on};
use hex::FromHex;
use jsonrpc_http_server::jsonrpc_core::serde_json::Value;
use jsonrpc_http_server::jsonrpc_core::Error as JsonRpcError;
use jsonrpc_http_server::jsonrpc_core::{IoHandler, Params};
use jsonrpc_http_server::{DomainsValidation, ServerBuilder};
use parity_scale_codec::{Decode, Encode};
use runtime::{AccountId, DotBalancesPallet, PolkaBtcProvider, SecurityPallet, VaultRegistryPallet};
use serde::{Deserialize, Deserializer};
use std::{collections::VecDeque, net::SocketAddr, time::SystemTime};
use std::sync::Arc;
use kv::*;
use chrono::{DateTime, TimeZone, NaiveDateTime, Utc};

fn parse_params<T: Decode>(params: Params) -> Result<T, Error> {
    let raw: [RawBytes; 1] = params.parse()?;
    let req = Decode::decode(&mut &raw[0].0[..]).map_err(Error::CodecError)?;
    Ok(req)
}

fn handle_resp<T: Encode>(resp: Result<T, Error>) -> Result<Value, JsonRpcError> {
    match resp {
        Ok(data) => Ok(format!("0x{}", hex::encode(data.encode())).into()),
        Err(_) => Err(JsonRpcError::internal_error()),
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

#[derive(Encode, Decode, Debug)]
struct FundAccountJsonRpcRequest {
    pub account_id: AccountId,
    pub amount: u128,
}

async fn _fund_account_raw(api: &Arc<PolkaBtcProvider>, params: Params, cfg: Config) -> Result<(), Error> {
    let req: FundAccountJsonRpcRequest = parse_params(params)?;
    _fund_account(api, req, cfg).await.unwrap();
    Ok(())
}

async fn get_faucet_amount(provider: &Arc<PolkaBtcProvider>, id: AccountId) -> u128 {
    let req_vault = provider.get_vault(id.clone()).await;
    // provider.
    match req_vault {
        Ok(_) => {
            println!("Funding suceeded");
            100_000_000
        },
        Err(_) => 1_000
    }
}

// TODO: transfer DOT from configured account
async fn _fund_account(api: &Arc<PolkaBtcProvider>, req: FundAccountJsonRpcRequest, cfg: Config) -> Result<(), Error> {
    let provider = api.clone();
    let store = Store::new(cfg)
        .expect("Unable to open kv store");
    let kv = store.bucket::<String, Json<VecDeque<String>>>(Some("store"))
        .expect("Unable to create kv store bucket");
    
    let kv_query = kv.get(req.account_id.to_string()).unwrap();

    let requests = match kv_query {
        Some(value) => value.0,
        None => VecDeque::new(),
    };

    // invalidate requests older than one hour
    // ensure there are no requests left

    requests.iter().filter(|request_datetime_string| DateTime::parse_from_str(request_datetime_string)

    let amount = get_faucet_amount(&provider, req.account_id.clone()).await;
    block_on(
        provider.transfer_to(req.account_id, amount),
    )?;
    Ok(())
}

pub async fn start(api: Arc<PolkaBtcProvider>, addr: SocketAddr, origin: String) {
    let mut io = IoHandler::default();
    let api = api.clone();
    {
        let api = api.clone();
        io.add_sync_method("system_health", move |_| {handle_resp(_system_health(&api))});
    }
    {
        let api = api.clone();
        // an async closure is only FnOnce, so doesn't work
        // we need this workaround as suggested here
        // https://stackoverflow.com/questions/62383234/why-does-capturing-an-arc-by-move-make-my-closure-fnonce-not-fn
        io.add_method("fund_account", move |params| {
            let api = api.clone();
            async move {
                let result = _fund_account_raw(&api.clone(), params, Config::new("./kv")).await;
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
    use std::sync::Arc;

    use futures::{executor::block_on, future::ok};
    use kv::Config;
    use log::{debug, info};
    use runtime::{AccountId, VaultRegistryPallet, PolkaBtcRuntime, BtcAddress};

    use super::{DotBalancesPallet, FundAccountJsonRpcRequest, PolkaBtcProvider, _fund_account};
    use sp_core::H160;
    use sp_keyring::AccountKeyring;
    use substrate_subxt::PairSigner;
    use substrate_subxt_client::{
        DatabaseConfig, KeystoreConfig, Role, SubxtClient, SubxtClientConfig,
    };
    use tempdir::TempDir;
    use jsonrpsee::{
        common::{to_value as to_json_value},
    };
    use jsonrpsee::Client as JsonRpseeClient;

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
    
    #[tokio::test]
    async fn test_fund_account_basic() {
        env_logger::init();
        info!("[root] info");
        debug!("[root] debug");

        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let amount: u128 = 10000000000;
        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let alice_funds_before = alice_provider.get_free_dot_balance().await.unwrap();
        let bob_funds_before = alice_provider.get_free_dot_balance_for_id(bob_account_id.clone()).await.unwrap();
        println!("Alice: {}", alice_funds_before);
        println!("Bob: {}", bob_funds_before);
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            amount
        };

        let cfg = Config::new("./kv");
        match _fund_account(&Arc::from(alice_provider.clone()), req, cfg).await {
            Ok(_) => {
                println!("Funding suceeded")
            },
            Err(e) => eprintln!("Funding error: {}", e)
        }

        let alice_funds_after = alice_provider.get_free_dot_balance().await.unwrap();
        let bob_funds_after = alice_provider.get_free_dot_balance_for_id(bob_account_id).await.unwrap();
        println!("Alice {}", alice_funds_after);
        println!("Bob {}", bob_funds_after);

        assert_eq!(bob_funds_before + amount, bob_funds_after);
    }

    #[tokio::test]
    async fn test_fund_account_vault() {
        env_logger::init();
        info!("[root] info");
        debug!("[root] debug");

        let (client, tmp_dir) = default_provider_client(AccountKeyring::Alice).await;
        let bob_account_id: AccountId = AccountKeyring::Bob.to_account_id();
        let amount: u128 = 10000000000;

        let bob_provider = setup_provider(client.clone(), AccountKeyring::Bob).await;
        let bob_vault_address = BtcAddress::P2PKH(H160::random());
        bob_provider.register_vault(100, bob_vault_address).await.unwrap();
        

        let alice_provider = setup_provider(client.clone(), AccountKeyring::Alice).await;
        let alice_funds_before = alice_provider.get_free_dot_balance().await.unwrap();
        let bob_funds_before = alice_provider.get_free_dot_balance_for_id(bob_account_id.clone()).await.unwrap();
        println!("Alice: {}", alice_funds_before);
        println!("Bob: {}", bob_funds_before);
        let req = FundAccountJsonRpcRequest {
            account_id: bob_account_id.clone(),
            amount
        };

        let cfg = Config::new("./kv");
        match _fund_account(&Arc::from(alice_provider.clone()), req, cfg).await {
            Ok(_) => {
                println!("Funding suceeded")
            },
            Err(e) => eprintln!("Funding error: {}", e)
        }

        let alice_funds_after = alice_provider.get_free_dot_balance().await.unwrap();
        let bob_funds_after = alice_provider.get_free_dot_balance_for_id(bob_account_id).await.unwrap();
        println!("Alice {}", alice_funds_after);
        println!("Bob {}", bob_funds_after);

        assert_eq!(bob_funds_before + amount, bob_funds_after);
    }

}


