use crate::Error;
use runtime::historic_event_types::*;
use runtime::{
    pallets::issue::{CancelIssueEvent, ExecuteIssueEvent, RequestIssueEvent},
    pallets::redeem::{CancelRedeemEvent, ExecuteRedeemEvent, RequestRedeemEvent},
    PolkaBtcProvider, PolkaBtcRuntime,
};
use std::fs::File;
use std::path::Path;

const OUTPUT_FOLDER_NAME: &str = "event-logs";

pub async fn dump_raw_events(provider: &PolkaBtcProvider) -> Result<(), Error> {
    provider
        .on_past_events(|event| println!("{:?}", event))
        .await?;
    Ok(())
}

#[rustfmt::skip]
pub async fn dump_json(provider: &PolkaBtcProvider) -> Result<(), Error> {
    let output_folder = Path::new(OUTPUT_FOLDER_NAME);
    if !output_folder.is_dir() {
        std::fs::create_dir(output_folder)?;
    }
    
    let mut issue_requests = vec![];
    let mut issue_executes = vec![];
    let mut issue_cancelations = vec![];
    let mut redeem_requests = vec![];
    let mut redeem_executes = vec![];
    let mut redeem_cancelations = vec![];
    
    provider
        .on_past_events(|event| match event {
            Event::issue(x) => match x {
                IssueEvent::RequestIssue(issue_id, requester, amount, vault_id, btc_address) => {
                    issue_requests.push(RequestIssueEvent::<PolkaBtcRuntime> {
                        issue_id, requester, amount, vault_id, btc_address 
                    });
                }
                IssueEvent::CancelIssue(issue_id, requester) => {
                    issue_executes.push(CancelIssueEvent::<PolkaBtcRuntime> {
                        issue_id, requester,
                    });
                }
                IssueEvent::ExecuteIssue(issue_id, requester, vault_id) => {
                    issue_cancelations.push(ExecuteIssueEvent::<PolkaBtcRuntime> {
                        issue_id, requester, vault_id,
                    });
                }
            },
            Event::redeem(x) => match x {
                RedeemEvent::RequestRedeem(
                    redeem_id, redeemer, amount_polka_btc, vault_id, btc_address,
                ) => {
                    redeem_requests.push(RequestRedeemEvent::<PolkaBtcRuntime> {
                        redeem_id, redeemer, amount_polka_btc, vault_id, btc_address,
                    });
                }
                RedeemEvent::CancelRedeem(redeem_id, redeemer) => {
                    redeem_cancelations.push(CancelRedeemEvent::<PolkaBtcRuntime> {
                        redeem_id, redeemer,
                    });
                }
                RedeemEvent::ExecuteRedeem(redeem_id, redeemer, vault_id) => {
                    redeem_executes.push(ExecuteRedeemEvent::<PolkaBtcRuntime> {
                        redeem_id, redeemer, vault_id,
                    });
                }
            },
            _ => {}
        })
        .await?;

    serde_json::to_writer_pretty(
        File::create(output_folder.join("issue-requests.json"))?, 
        &issue_requests)?;
    serde_json::to_writer_pretty(
        File::create(output_folder.join("issue-cancelations.json"))?, 
        &issue_cancelations)?;
    serde_json::to_writer_pretty(
        File::create(output_folder.join("issue-executes.json"))?, 
        &issue_executes)?;
    serde_json::to_writer_pretty(
        File::create(output_folder.join("redeem-requests.json"))?, 
        &redeem_requests)?;
    serde_json::to_writer_pretty(
        File::create(output_folder.join("redeem-cancelations.json"))?, 
        &redeem_cancelations)?;
    serde_json::to_writer_pretty(
        File::create(output_folder.join("redeem-executes.json"))?, 
        &redeem_executes)?;

    println!("Wrote json files to {}", OUTPUT_FOLDER_NAME);

    Ok(())
}

pub async fn report_chain_stats(provider: &PolkaBtcProvider) -> Result<(), Error> {
    let mut issue_requests = vec![];
    let mut issue_executes = vec![];
    let mut redeem_requests = vec![];
    let mut redeem_executes = vec![];

    provider
        .on_past_events(|event| match event {
            Event::issue(IssueEvent::RequestIssue(id, _, amount, _, _)) => {
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
        })
        .await?;

    let issue_executes = issue_executes
        .into_iter()
        .map(|id| {
            issue_requests
                .iter()
                .find(|&x| x.0 == id)
                .expect("ExecuteIssue did not have corresponding RequestIssue")
                .1
        })
        .collect::<Vec<_>>();

    let redeem_executes = redeem_executes
        .into_iter()
        .map(|id| {
            redeem_requests
                .iter()
                .find(|&x| x.0 == id)
                .expect("ExecuteRedeem did not have corresponding RequestRedeem")
                .1
        })
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
