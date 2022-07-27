use crate::error::Error;
use codec::{Decode, Encode};
use jsonrpsee::{
    core::client::{Client as WsClient, ClientT},
    rpc_params,
    ws_client::WsClientBuilder,
};
use reqwest::Url;
use sp_core::Bytes;
use sp_core_hashing::twox_128;

use std::{
    env,
    fmt::Debug,
    fs::{self, File},
    io::{copy, Cursor},
    os::unix::prelude::PermissionsExt,
    process::{Command, Stdio},
    str,
};

pub const PARACHAIN_MODULE: &str = "VaultRegistry";
pub const RELEASE_VERSION_STORAGE_ITEM: &str = "CurrentClientRelease";

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

pub async fn get_release_uri(ws_client: &WsClient) -> Result<String, Error> {
    let storage_key = compute_storage_key(PARACHAIN_MODULE.to_string(), RELEASE_VERSION_STORAGE_ITEM.to_string());
    let release_uri = read_chain_storage::<String>(ws_client, Some(storage_key.as_str())).await?;
    Ok(release_uri)
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

/// Does not download if a file with the same name already exists
pub async fn try_download_client_binary(release_uri: String) -> Result<String, Error> {
    let parsed_uri = Url::parse(&release_uri)?;
    let bin_name = parsed_uri
        .path_segments()
        .and_then(|segments| segments.last())
        .and_then(|name| if name.is_empty() { None } else { Some(name) })
        .ok_or(Error::ClientNameDerivationError)?;

    let dir = env::current_dir()?;
    let bin_path = dir.join(bin_name);
    if bin_path.as_path().exists() {
        log::warn!("Vault binary already exists, skipping download.");
        return Ok(bin_name.to_string());
    }
    println!("Downloading {} at: '{:?}'", bin_name, bin_path);
    let mut bin_file = File::create(bin_path.clone())?;

    let response = reqwest::get(release_uri.clone()).await?;
    let mut content = Cursor::new(response.bytes().await?);

    copy(&mut content, &mut bin_file)?;

    // Make the binary executable.
    // The set permissions are: -rwx------
    fs::set_permissions(bin_path, fs::Permissions::from_mode(0o700))?;

    Ok(bin_name.to_string())
}
