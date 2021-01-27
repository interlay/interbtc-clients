use crate::Error;
use log::*;
use runtime::historic_event_types::*;
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    pallets::redeem::{CancelRedeemEvent, ExecuteRedeemEvent, RequestRedeemEvent},
    PolkaBtcProvider, PolkaBtcRuntime,
};
use serde::Serialize;
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

pub async fn dump_raw_events(provider: &PolkaBtcProvider) -> Result<(), Error> {
    provider
        .on_past_events(None, None, |event, _| {
            println!("{:?}", event);
            Ok(())
        })
        .await?;
    Ok(())
}

/// Helper to write a JSON vec to disk
struct LogWriter {
    writer: BufWriter<File>,
    first_elem: bool,
}
impl LogWriter {
    fn new(folder: &Path, name: &str) -> Result<LogWriter, Error> {
        let file = File::create(folder.join(name))?;
        let mut writer = BufWriter::new(file);
        write!(writer, "[")?;
        Ok(LogWriter {
            writer,
            first_elem: true,
        })
    }
    /// Write one element to the disk
    fn write<T: Serialize>(&mut self, elem: T) -> Result<(), Error> {
        let output = serde_json::to_string_pretty(&elem)?;
        if self.first_elem {
            write!(self.writer, "\n{}", output)?;
            self.first_elem = false;
        } else {
            write!(self.writer, ",\n{}", output)?;
        }
        Ok(())
    }
}
impl Drop for LogWriter {
    /// write the end-of-array identifier to disk when to writer goes out of scope
    fn drop(&mut self) {
        if let Err(_) = write!(self.writer, "\n]") {
            log::error!("Failed to write closing bracket to file");
        }
    }
}

#[rustfmt::skip]
pub async fn dump_json(provider: &PolkaBtcProvider, output_folder_name: &str) -> Result<(), Error> {
    let output_folder = Path::new(output_folder_name);
    if !output_folder.is_dir() {
        std::fs::create_dir_all(output_folder)?;
    }
    
    let mut issue_requests = LogWriter::new(output_folder, "issue-requests.json")?;
    let mut issue_cancellations = LogWriter::new(output_folder, "issue-cancellations.json")?;
    let mut issue_executions = LogWriter::new(output_folder, "issue-executions.json")?;
    let mut redeem_requests = LogWriter::new(output_folder, "redeem-requests.json")?;
    let mut redeem_cancellations = LogWriter::new(output_folder, "redeem-cancellations.json")?;
    let mut redeem_executions = LogWriter::new(output_folder, "redeem-executions.json")?;

    provider
        .on_past_events(None, None, |event, num_blocks_remaining| {
            info!("{} blocks remaining..", num_blocks_remaining);
            match event {
                Event::issue(x) => match x {
                    IssueEvent::RequestIssue(issue_id, requester, amount, vault_id, btc_address, public_key) => {
                        issue_requests.write(RequestIssueEvent::<PolkaBtcRuntime> {
                            issue_id, requester, amount, vault_id, btc_address, public_key
                        })?;
                    }
                    IssueEvent::CancelIssue(issue_id, requester) => {
                        issue_cancellations.write(CancelIssueEvent::<PolkaBtcRuntime> {
                            issue_id, requester,
                        })?;
                    }
                    IssueEvent::ExecuteIssue(issue_id, requester, vault_id) => {
                        issue_executions.write(ExecuteIssueEvent::<PolkaBtcRuntime> {
                            issue_id, requester, vault_id,
                        })?;
                    }
                },
                Event::redeem(x) => match x {
                    RedeemEvent::RequestRedeem(
                        redeem_id, redeemer, amount_polka_btc, vault_id, btc_address,
                    ) => {
                        redeem_requests.write(RequestRedeemEvent::<PolkaBtcRuntime> {
                            redeem_id, redeemer, amount_polka_btc, vault_id, btc_address,
                        })?;
                    }
                    RedeemEvent::LiquidationRedeem(
                        _, _
                    ) => {
              
                    }
                    RedeemEvent::CancelRedeem(redeem_id, redeemer) => {
                        redeem_cancellations.write(CancelRedeemEvent::<PolkaBtcRuntime> {
                            redeem_id, redeemer,
                        })?;
                    }
                    RedeemEvent::ExecuteRedeem(redeem_id, redeemer, vault_id) => {
                        redeem_executions.write(ExecuteRedeemEvent::<PolkaBtcRuntime> {
                            redeem_id, redeemer, vault_id,
                        })?;
                    }
                },
                _ => {}
            }
            Ok(())
        }).await?;

    println!("Wrote json files to {}", output_folder_name);

    Ok(())
}

/// Get issue and request statistics. Not that we may run out of memory when the number of
/// issues/redeems is very large
pub async fn report_chain_stats(
    provider: &PolkaBtcProvider,
    start: Option<u32>,
    end: Option<u32>,
) -> Result<(), Error> {
    let mut issue_requests = vec![];
    let mut issue_executes = vec![];
    let mut redeem_requests = vec![];
    let mut redeem_executes = vec![];

    provider
        .on_past_events(start, end, |event, num_blocks_remaining| {
            info!("{} blocks remaining..", num_blocks_remaining);
            match event {
                Event::issue(IssueEvent::RequestIssue(id, _, amount, _, _, _)) => {
                    issue_requests.push((id, amount));
                }
                Event::issue(IssueEvent::ExecuteIssue(id, _, _)) => {
                    issue_executes.push(id);
                }
                Event::redeem(RedeemEvent::RequestRedeem(id, _, amount, _, _)) => {
                    redeem_requests.push((id, amount));
                }
                Event::redeem(RedeemEvent::ExecuteRedeem(id, _, _)) => {
                    redeem_executes.push(id);
                }
                _ => {}
            }
            Ok(())
        })
        .await?;

    let issue_executes = issue_executes
        .into_iter()
        .filter_map(|id| Some(issue_requests.iter().find(|&x| x.0 == id)?.1))
        .collect::<Vec<_>>();

    let redeem_executes = redeem_executes
        .into_iter()
        .filter_map(|id| Some(redeem_requests.iter().find(|&x| x.0 == id)?.1))
        .collect::<Vec<_>>();

    println!(
        "{} issues executed for a total amount of {}",
        issue_executes.iter().len(),
        issue_executes.iter().fold(0, |acc, e| acc + e)
    );
    println!(
        "{} redeems executed for a total amount of {}",
        redeem_executes.iter().len(),
        redeem_executes.iter().fold(0, |acc, e| acc + e)
    );

    Ok(())
}
