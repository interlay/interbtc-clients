use futures::{
    channel::mpsc,
    future::{select, FutureExt},
    sink::SinkExt,
    stream::StreamExt,
};
use jsonrpsee_core::{
    async_trait,
    client::{Client as JsonRpcClient, TransportReceiverT, TransportSenderT},
};
use sc_network::config::TransportConfig;
pub use sc_service::{
    config::{DatabaseSource, KeystoreConfig, WasmExecutionMethod, WasmtimeInstantiationStrategy},
    Error as ServiceError,
};
use sc_service::{
    config::{NetworkConfiguration, TelemetryEndpoints},
    ChainSpec, Configuration, KeepBlocks, RpcHandlers, TaskManager,
};
pub use sp_keyring::AccountKeyring;
use thiserror::Error;
use tokio::task;

/// Error thrown by the client.
#[derive(Debug, Error)]
pub enum SubxtClientError {
    /// Failed to parse json rpc message.
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// Channel closed.
    #[error("{0}")]
    Mpsc(#[from] mpsc::SendError),
}

/// Sending end.
pub struct Sender(mpsc::UnboundedSender<String>);

/// Receiving end
pub struct Receiver(mpsc::UnboundedReceiver<String>);

#[async_trait]
impl TransportSenderT for Sender {
    type Error = SubxtClientError;

    async fn send(&mut self, msg: String) -> Result<(), Self::Error> {
        self.0.send(msg).await?;
        Ok(())
    }
}

#[async_trait]
impl TransportReceiverT for Receiver {
    type Error = SubxtClientError;

    async fn receive(&mut self) -> Result<String, Self::Error> {
        let msg = self.0.next().await.expect("channel should be open");
        Ok(msg)
    }
}

/// Client for an embedded substrate node.
pub struct SubxtClient {
    rpc: RpcHandlers,
    sender: Sender,
    receiver: Receiver,
}

impl SubxtClient {
    /// Create a new client.
    pub fn new(mut task_manager: TaskManager, rpc: RpcHandlers) -> Self {
        let (to_back, from_front) = mpsc::unbounded();
        let (to_front, from_back) = mpsc::unbounded();

        let rpc_copy = rpc.clone();
        task::spawn(
            select(
                Box::pin(from_front.for_each(move |message: String| {
                    let rpc = rpc.clone();
                    let mut to_front = to_front.clone();
                    async move {
                        let (resp, mut stream) = rpc.rpc_query(&message).await.unwrap();
                        to_front.send(resp).await.ok();
                        // read the rest of the stream but don't block
                        task::spawn(async move {
                            while let Some(resp) = stream.next().await {
                                to_front.send(resp).await.ok();
                            }
                        });
                    }
                })),
                Box::pin(async move {
                    task_manager.future().await.ok();
                }),
            )
            .map(drop),
        );

        Self {
            rpc: rpc_copy,
            sender: Sender(to_back),
            receiver: Receiver(from_back),
        }
    }

    /// Creates a new client from a config.
    pub fn from_config<C: ChainSpec + 'static>(
        config: SubxtClientConfig<C>,
        builder: impl Fn(Configuration) -> Result<(TaskManager, RpcHandlers), ServiceError>,
    ) -> Result<Self, ServiceError> {
        let config = config.into_service_config();
        let (task_manager, rpc_handlers) = (builder)(config)?;
        Ok(Self::new(task_manager, rpc_handlers))
    }
}

impl Clone for SubxtClient {
    fn clone(&self) -> Self {
        let (to_back, from_front) = mpsc::unbounded();
        let (to_front, from_back) = mpsc::unbounded();

        let rpc = self.rpc.clone();
        task::spawn(Box::pin(from_front.for_each(move |message: String| {
            let rpc = rpc.clone();
            let mut to_front = to_front.clone();
            async move {
                let (resp, mut stream) = rpc.rpc_query(&message).await.unwrap();
                to_front.send(resp).await.ok();
                // read the rest of the stream but don't block
                task::spawn(async move {
                    while let Some(resp) = stream.next().await {
                        to_front.send(resp).await.ok();
                    }
                });
            }
        })));

        Self {
            rpc: self.rpc.clone(),
            sender: Sender(to_back),
            receiver: Receiver(from_back),
        }
    }
}

impl From<SubxtClient> for JsonRpcClient {
    fn from(client: SubxtClient) -> Self {
        (client.sender, client.receiver).into()
    }
}

/// Role of the node.
#[derive(Clone, Copy, Debug)]
pub enum Role {
    /// Light client.
    Light,
    /// A full node (mainly used for testing purposes).
    Authority(AccountKeyring),
}

impl From<Role> for sc_service::Role {
    fn from(role: Role) -> Self {
        match role {
            Role::Light => Self::Light,
            Role::Authority(_) => Self::Authority,
        }
    }
}

impl From<Role> for Option<String> {
    fn from(role: Role) -> Self {
        match role {
            Role::Light => None,
            Role::Authority(key) => Some(key.to_seed()),
        }
    }
}

/// Client configuration.
#[derive(Clone)]
pub struct SubxtClientConfig<C: ChainSpec + 'static> {
    /// Name of the implementation.
    pub impl_name: &'static str,
    /// Version of the implementation.
    pub impl_version: &'static str,
    /// Author of the implementation.
    pub author: &'static str,
    /// Copyright start year.
    pub copyright_start_year: i32,
    /// Database configuration.
    pub db: DatabaseSource,
    /// Keystore configuration.
    pub keystore: KeystoreConfig,
    /// Chain specification.
    pub chain_spec: C,
    /// Role of the node.
    pub role: Role,
    /// Enable telemetry on the given port.
    pub telemetry: Option<u16>,
    /// Wasm execution method
    pub wasm_method: WasmExecutionMethod,
    /// Handle to the tokio runtime. Will be used to spawn futures by the task manager.
    pub tokio_handle: tokio::runtime::Handle,
}

impl<C: ChainSpec + 'static> SubxtClientConfig<C> {
    /// Creates a service configuration.
    pub fn into_service_config(self) -> Configuration {
        let mut network = NetworkConfiguration::new(
            format!("{} (subxt client)", self.chain_spec.name()),
            "unknown",
            Default::default(),
            None,
        );
        network.boot_nodes = self.chain_spec.boot_nodes().to_vec();
        network.transport = TransportConfig::Normal {
            enable_mdns: true,
            allow_private_ipv4: true,
            // wasm_external_transport: None,
        };
        let telemetry_endpoints = if let Some(port) = self.telemetry {
            let endpoints = TelemetryEndpoints::new(vec![(format!("/ip4/127.0.0.1/tcp/{}/ws", port), 0)])
                .expect("valid config; qed");
            Some(endpoints)
        } else {
            None
        };
        let service_config = Configuration {
            network,
            impl_name: self.impl_name.to_string(),
            impl_version: self.impl_version.to_string(),
            chain_spec: Box::new(self.chain_spec),
            role: self.role.into(),
            database: self.db,
            keystore: self.keystore,
            max_runtime_instances: 8,
            announce_block: true,
            dev_key_seed: self.role.into(),
            telemetry_endpoints,
            tokio_handle: self.tokio_handle,
            default_heap_pages: Default::default(),
            disable_grandpa: Default::default(),
            execution_strategies: Default::default(),
            force_authoring: Default::default(),
            keep_blocks: KeepBlocks::All,
            keystore_remote: Default::default(),
            offchain_worker: Default::default(),
            prometheus_config: Default::default(),
            rpc_cors: Default::default(),
            rpc_http: Default::default(),
            rpc_ipc: Default::default(),
            rpc_ws: Default::default(),
            rpc_ws_max_connections: Default::default(),
            rpc_methods: Default::default(),
            state_cache_child_ratio: Default::default(),
            state_cache_size: Default::default(),
            tracing_receiver: Default::default(),
            tracing_targets: Default::default(),
            transaction_pool: Default::default(),
            wasm_method: self.wasm_method,
            base_path: Default::default(),
            informant_output_format: Default::default(),
            state_pruning: Default::default(),
            // transaction_storage: sc_client_db::TransactionStorageMode::BlockBody,
            wasm_runtime_overrides: Default::default(),
            rpc_max_payload: Default::default(),
            ws_max_out_buffer_capacity: Default::default(),
            runtime_cache_size: 2,
            rpc_max_request_size: None,
            rpc_max_response_size: None,
            rpc_id_provider: None,
            rpc_max_subs_per_conn: None,
        };

        log::info!("{}", service_config.impl_name);
        log::info!("✌️  version {}", service_config.impl_version);
        log::info!("❤️  by {}, {}", self.author, self.copyright_start_year);
        log::info!("📋 Chain specification: {}", service_config.chain_spec.name());
        log::info!("🏷  Node name: {}", service_config.network.node_name);
        log::info!("👤 Role: {:?}", self.role);

        service_config
    }
}
