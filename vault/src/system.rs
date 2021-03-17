use crate::{
    collateral::lock_required_collateral, constants::*, faucet, issue, service::*, Error, IssueRequests, RequestEvent,
};
use async_trait::async_trait;
use bitcoin::{BitcoinCore, BitcoinCoreApi};
use futures::{channel::mpsc, SinkExt};
use log::*;
use runtime::{
    pallets::sla::UpdateVaultSLAEvent, wait_or_shutdown, AccountId, BtcRelayPallet, Error as RuntimeError,
    PolkaBtcHeader, PolkaBtcProvider, PolkaBtcRuntime, Service, ShutdownReceiver, UtilFuncs, VaultRegistryPallet,
};
use std::{sync::Arc, time::Duration};
use tokio::time::delay_for;

#[derive(Clone)]
pub struct VaultServiceConfig {
    /// the bitcoin RPC handle
    pub bitcoin_core: BitcoinCore,
    pub auto_register_with_collateral: Option<u128>,
    pub auto_register_with_faucet_url: Option<String>,
    pub rpc_cors_domain: String,
    pub no_startup_collateral_increase: bool,
    pub btc_confirmations: Option<u32>,
    pub max_collateral: u128,
    pub no_auto_replace: bool,
    pub no_auto_auction: bool,
    pub no_issue_execution: bool,
    pub collateral_timeout: Duration,
}

pub struct VaultService {
    btc_parachain: PolkaBtcProvider,
    config: VaultServiceConfig,
    handle: tokio::runtime::Handle,
    shutdown: ShutdownReceiver,
}

#[async_trait]
impl Service<VaultServiceConfig, PolkaBtcProvider> for VaultService {
    async fn start(
        btc_parachain: PolkaBtcProvider,
        config: VaultServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownReceiver,
    ) -> Result<(), RuntimeError> {
        VaultService::new(btc_parachain, config, handle, shutdown)
            .run_service()
            .await
            .map_err(|_| RuntimeError::ChannelClosed)
    }
}

impl VaultService {
    fn new(
        btc_parachain: PolkaBtcProvider,
        config: VaultServiceConfig,
        handle: tokio::runtime::Handle,
        shutdown: ShutdownReceiver,
    ) -> Self {
        Self {
            btc_parachain,
            config,
            handle,
            shutdown,
        }
    }

    async fn run_service(&self) -> Result<(), Error> {
        let bitcoin_core = self.config.bitcoin_core.clone();
        let handle = self.handle.clone();

        let vault_id = self.btc_parachain.get_account_id().clone();

        let num_confirmations = match self.config.btc_confirmations {
            Some(x) => x,
            None => self.btc_parachain.get_bitcoin_confirmations().await?,
        };
        info!("Using {} bitcoin confirmations", num_confirmations);

        if let Some(collateral) = self.config.auto_register_with_collateral {
            if !is_registered(&self.btc_parachain, vault_id.clone()).await? {
                // bitcoin core is currently blocking, no need to try_join
                let public_key = bitcoin_core.get_new_public_key().await?;
                self.btc_parachain.register_vault(collateral, public_key).await?;
                info!("Automatically registered vault");
            } else {
                info!("Not registering vault -- already registered");
            }
        } else if let Some(faucet_url) = &self.config.auto_register_with_faucet_url {
            if !is_registered(&self.btc_parachain, vault_id.clone()).await? {
                faucet::fund_and_register(&self.btc_parachain, &bitcoin_core, faucet_url, vault_id.clone()).await?;
                info!("Automatically registered vault");
            } else {
                info!("Not registering vault -- already registered");
            }
        }

        if let Ok(vault) = self.btc_parachain.get_vault(vault_id.clone()).await {
            if !bitcoin_core.wallet_has_public_key(vault.wallet.public_key).await? {
                return Err(bitcoin::Error::MissingPublicKey.into());
            }
        }

        issue::add_keys_from_past_issue_request(&self.btc_parachain, &bitcoin_core).await?;

        let open_request_executor =
            execute_open_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations);
        handle.spawn(async move {
            info!("Checking for open replace/redeem requests...");
            match open_request_executor.await {
                Ok(_) => info!("Done processing open replace/redeem requests"),
                Err(e) => error!("Failed to process open replace/redeem requests: {}", e),
            }
        });

        if !self.config.no_startup_collateral_increase {
            // check if the vault is registered
            match lock_required_collateral(self.btc_parachain.clone(), vault_id.clone(), self.config.max_collateral)
                .await
            {
                Err(Error::RuntimeError(runtime::Error::VaultNotFound)) => {} // not registered
                Err(e) => error!("Failed to lock required additional collateral: {}", e),
                _ => {} // collateral level now OK
            };
        }

        let collateral_maintainer = wait_or_shutdown(
            self.shutdown.clone(),
            maintain_collateralization_rate(self.btc_parachain.clone(), self.config.max_collateral),
        );

        // wait for a new block to arrive, to prevent processing an event that potentially
        // has been processed already prior to restarting
        info!("Waiting for new block...");
        let startup_height = self.btc_parachain.get_current_chain_height().await?;
        while startup_height == self.btc_parachain.get_current_chain_height().await? {
            delay_for(CHAIN_HEIGHT_POLLING_INTERVAL).await;
        }
        info!("Starting to listen for events...");

        // issue handling
        let issue_set = Arc::new(IssueRequests::new());
        let (issue_event_tx, issue_event_rx) = mpsc::channel::<RequestEvent>(32);
        let (issue_block_tx, issue_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);

        let issue_request_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_requests(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                issue_event_tx.clone(),
                issue_set.clone(),
            ),
        );

        let issue_execute_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_executes(self.btc_parachain.clone(), issue_event_tx.clone(), issue_set.clone()),
        );

        let issue_cancel_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_issue_cancels(self.btc_parachain.clone(), issue_set.clone()),
        );

        let mut issue_cancellation_scheduler = CancellationScheduler::new(self.btc_parachain.clone(), vault_id.clone());

        let issue_block_provider = self.btc_parachain.clone();
        let issue_block_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let issue_block_tx = &issue_block_tx;
            issue_block_provider
                .on_block(move |header| async move {
                    issue_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    Ok(())
                })
                .await
        });

        let issue_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            issue_cancellation_scheduler
                .handle_cancellation::<IssueCanceller>(issue_block_rx, issue_event_rx)
                .await
        });

        let issue_executor = wait_or_shutdown(
            self.shutdown.clone(),
            execute_open_issue_requests(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                issue_set.clone(),
                num_confirmations,
            ),
        );

        // replace handling
        let (replace_event_tx, replace_event_rx) = mpsc::channel::<RequestEvent>(16);
        let (replace_block_tx, replace_block_rx) = mpsc::channel::<PolkaBtcHeader>(16);

        let request_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_replace_requests(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                replace_event_tx.clone(),
                !self.config.no_auto_replace,
            ),
        );

        let accept_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_accept_replace(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let execute_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_execute_replace(self.btc_parachain.clone(), replace_event_tx.clone()),
        );

        let auction_replace_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_auction_replace(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let mut replace_cancellation_scheduler =
            CancellationScheduler::new(self.btc_parachain.clone(), vault_id.clone());

        let replace_block_provider = self.btc_parachain.clone();
        let replace_block_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let replace_block_tx = &replace_block_tx;
            replace_block_provider
                .on_block(move |header| async move {
                    replace_block_tx
                        .clone()
                        .send(header.clone())
                        .await
                        .map_err(|_| RuntimeError::ChannelClosed)?;
                    Ok(())
                })
                .await
        });

        let replace_cancel_scheduler = wait_or_shutdown(self.shutdown.clone(), async move {
            replace_cancellation_scheduler
                .handle_cancellation::<ReplaceCanceller>(replace_block_rx, replace_event_rx)
                .await
        });

        let third_party_collateral_listener = wait_or_shutdown(
            self.shutdown.clone(),
            monitor_collateral_of_vaults(
                self.btc_parachain.clone(),
                bitcoin_core.clone(),
                replace_event_tx.clone(),
                self.config.collateral_timeout,
            ),
        );

        // redeem handling
        let redeem_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_redeem_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        // refund handling
        let refund_listener = wait_or_shutdown(
            self.shutdown.clone(),
            listen_for_refund_requests(self.btc_parachain.clone(), bitcoin_core.clone(), num_confirmations),
        );

        let sla_provider = self.btc_parachain.clone();
        let sla_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            let vault_id = sla_provider.get_account_id();
            sla_provider
                .on_event::<UpdateVaultSLAEvent<PolkaBtcRuntime>, _, _, _>(
                    |event| async move {
                        if &event.vault_id == vault_id {
                            info!("Received event: new total SLA score = {:?}", event.new_sla);
                        }
                    },
                    |err| error!("Error (UpdateVaultSLAEvent): {}", err.to_string()),
                )
                .await
        });

        let err_provider = self.btc_parachain.clone();
        let err_listener = wait_or_shutdown(self.shutdown.clone(), async move {
            err_provider
                .on_event_error(|e| debug!("Received error event: {}", e))
                .await
        });

        // misc copies of variables to move into spawn closures
        let no_auto_auction = self.config.no_auto_auction;
        let no_issue_execution = self.config.no_issue_execution;

        // starts all the tasks
        let _ = tokio::join!(
            // runs error listener to log errors
            handle.spawn(async move { err_listener.await }),
            // runs sla listener to log events
            handle.spawn(async move { sla_listener.await }),
            // maintain collateralization rate
            handle.spawn(async move {
                collateral_maintainer.await;
            }),
            // issue handling
            handle.spawn(async move { issue_request_listener.await }),
            handle.spawn(async move { issue_execute_listener.await }),
            handle.spawn(async move { issue_cancel_listener.await }),
            handle.spawn(async move { issue_block_listener.await }),
            handle.spawn(async move { issue_cancel_scheduler.await }),
            handle.spawn(async move {
                if !no_issue_execution {
                    let _ = issue_executor.await;
                }
            }),
            // replace handling
            handle.spawn(async move { request_replace_listener.await }),
            handle.spawn(async move { accept_replace_listener.await }),
            handle.spawn(async move { execute_replace_listener.await }),
            handle.spawn(async move { auction_replace_listener.await }),
            handle.spawn(async move { replace_block_listener.await }),
            handle.spawn(async move { replace_cancel_scheduler.await }),
            handle.spawn(async move {
                if !no_auto_auction {
                    let _ = third_party_collateral_listener.await;
                }
            }),
            // redeem handling
            handle.spawn(async move { redeem_listener.await }),
            // refund handling
            handle.spawn(async move { refund_listener.await }),
        );

        Ok(())
    }
}

pub(crate) async fn is_registered(provider: &PolkaBtcProvider, vault_id: AccountId) -> Result<bool, Error> {
    match provider.get_vault(vault_id).await {
        Ok(_) => Ok(true),
        Err(RuntimeError::VaultNotFound) => Ok(false),
        Err(err) => Err(err.into()),
    }
}
