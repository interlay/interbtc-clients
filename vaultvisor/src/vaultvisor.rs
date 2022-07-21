use crate::error::Error;
use codec::{Decode, Encode};
use jsonrpsee::{
    core::{
        client::{Client as WsClient, ClientT},
        JsonValue,
    },
    rpc_params,
    ws_client::WsClientBuilder,
};
use sp_core::Bytes;
use sp_core_hashing::twox_128;

use std::{
    fmt::Debug,
    process::{Command, Stdio},
    str,
};

pub const RELEASE_BASE_URL: &str = "https://github.com/interlay/interbtc-clients/releases/download";
pub const PARACHAIN_MODULE: &str = "VaultRegistry";
pub const RELEASE_VERSION_STORAGE_ITEM: &str = "LatestClientRelease";

#[derive(Encode, Decode, Default, Eq, PartialEq, Debug)]
pub struct RawClientRelease {
    /// The semver version, where the zero-index element is the major version
    pub version: [u32; 3],
    /// SHA256 checksum of the client binary
    pub checksum: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ClientRelease {
    // `checksum` not currently included on purpose, as it is not yet used.
    pub uri: String,
    pub binary_name: String,
    pub semver_version: String,
}

pub(crate) fn compute_storage_key(module: String, key: String) -> String {
    let module = twox_128(module.as_bytes());
    let item = twox_128(key.as_bytes());
    let key = hex::encode([module, item].concat());
    format!("0x{}", key)
}

pub async fn query_storage<'a>(
    ws_client: &'a WsClient,
    maybe_storage_key: Option<&str>,
    method: &str,
) -> Result<Bytes, Error> {
    let params = maybe_storage_key.map_or(rpc_params![], |key| rpc_params![key]);
    ws_client.request(method, params).await.map_err(Into::into)
}

pub async fn read_chain_storage<T: Decode + Debug>(
    ws_client: &WsClient,
    maybe_storage_key: Option<&str>,
) -> Result<T, Error> {
    let encoded_bytes = query_storage(ws_client, maybe_storage_key, "state_getStorage").await?;
    let v = encoded_bytes.to_vec();
    let decoded_entry = T::decode(&mut &v[..])?;
    Ok(decoded_entry)
    // TODO: To test this, merge this parachain PR: https://github.com/interlay/interbtc/pull/668
    // Then the metadata needs to be updated in interbtc-clients, so a standalone parachain provider can be
    // instantiated, as in the other integration tests. With that, it will be possible to simulate sending extrinsics
    // to upgrade the clients version.
}

pub async fn get_release_version(ws_client: &WsClient) -> Result<String, Error> {
    let storage_key = compute_storage_key(PARACHAIN_MODULE.to_string(), RELEASE_VERSION_STORAGE_ITEM.to_string());
    let release = read_chain_storage::<RawClientRelease>(ws_client, Some(storage_key.as_str())).await?;
    // Convert version array (e.g. `[1, 0, 0]`) to semver (e.g. `1.0.0`)
    // Assumes the version is always three elements long
    Ok(format!(
        "{}.{}.{}",
        release.version[0], release.version[1], release.version[2]
    ))
}

pub async fn get_binary_name(ws_client: &WsClient) -> Result<String, Error> {
    let runtime_version = ws_client
        .request::<JsonValue>("state_getRuntimeVersion", rpc_params![])
        .await?;
    let spec_name = runtime_version
        .as_object()
        .ok_or(Error::ClientNameDerivationError)?
        .get("specName")
        .ok_or(Error::ClientNameDerivationError)?
        .as_str()
        .ok_or(Error::ClientNameDerivationError)?
        .to_string();
    Ok(spec_name_to_vault_binary(spec_name))
}

fn spec_name_to_vault_binary(spec_name: String) -> String {
    // This function is based on the chainspec chain identification logic in the parachain.
    // Source: https://github.com/interlay/interbtc/blob/594d4d023f74fb7a6e935ad71f4292ca949779ed/parachain/src/command.rs#L50
    let base_name = "vault-";
    let suffix = if spec_name.starts_with("interlay") {
        "parachain-metadata-interlay"
    } else if spec_name.starts_with("kintsugi") {
        "parachain-metadata-kintsugi"
    } else if spec_name.starts_with("testnet-interlay") {
        "parachain-metadata-interlay-testnet"
    } else if spec_name.starts_with("testnet-kintsugi") || spec_name.starts_with("testnet-parachain") {
        "parachain-metadata-testnet-kintsugi"
    } else {
        // standalone node
        "standalone-metadata"
    };
    format!("{}{}", base_name, suffix)
}

pub async fn get_release(ws_client: &WsClient) -> Result<ClientRelease, Error> {
    let version = get_release_version(ws_client).await?;
    let binary_name = get_binary_name(ws_client).await?;
    let uri = format!("{}/{}/{}", RELEASE_BASE_URL, version, binary_name);
    Ok(ClientRelease {
        uri,
        binary_name,
        semver_version: version,
    })
}

pub async fn ws_client(url: &str) -> Result<WsClient, Error> {
    Ok(WsClientBuilder::default().build(url).await?)
}

pub async fn run_vault_binary(binary_name: &str, args: Vec<String>) -> Result<(), Error> {
    Command::new(format!("./{}", binary_name))
        .args(args)
        .stdout(Stdio::inherit())
        .spawn()?
        .wait_with_output()?;
    Ok(())
}

pub fn does_vault_binary_exist(release: &ClientRelease) -> Result<bool, Error> {
    // TODO: check if the existing binary has the correct version and do not crash.
    let output = Command::new("ls")
        .arg(release.binary_name.clone())
        .stdout(Stdio::piped())
        .output()?;
    // The `ls` command prints results followed by an endline. Remove the endline charachter.
    let stdout = String::from_utf8(output.stdout).unwrap().replace('\n', "");
    Ok(stdout.eq(&release.binary_name))
}
