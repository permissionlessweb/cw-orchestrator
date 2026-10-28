//! What this custody backend is willing to put in front of the phone.
//! Default: ICS20 transfers out and LP open/close/withdraw, plus the spends
//! and outputs that fund them; outputs only to the pinned account unless the
//! destination is allow-listed.

use anyhow::{bail, Result};
use penumbra_sdk_keys::{Address, FullViewingKey};
use penumbra_sdk_transaction::{ActionPlan, TransactionPlan};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub fn kind(a: &ActionPlan) -> &'static str {
    match a {
        ActionPlan::Spend(_) => "spend",
        ActionPlan::Output(_) => "output",
        ActionPlan::Ics20Withdrawal(_) => "ics20_withdrawal",
        ActionPlan::PositionOpen(_) => "position_open",
        ActionPlan::PositionClose(_) => "position_close",
        ActionPlan::PositionWithdraw(_) => "position_withdraw",
        ActionPlan::Swap(_) => "swap",
        ActionPlan::SwapClaim(_) => "swap_claim",
        ActionPlan::Delegate(_) => "delegate",
        ActionPlan::Undelegate(_) => "undelegate",
        ActionPlan::UndelegateClaim(_) => "undelegate_claim",
        ActionPlan::DelegatorVote(_) => "delegator_vote",
        ActionPlan::ActionLiquidityTournamentVote(_) => "lqt_vote",
        _ => "unsupported",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Expected `transaction_parameters.chain_id` (e.g. `penumbra-1`). Empty = any.
    pub chain_id: String,
    pub allowed_actions: Vec<String>,
    /// Penumbra addresses (bech32m) that outputs may pay besides the pinned account.
    pub allowed_output_addresses: Vec<String>,
    /// Remote-chain receivers allowed for ICS20 withdrawals. Empty = any.
    pub allowed_ics20_receivers: Vec<String>,
    /// Source channels allowed for ICS20 withdrawals (e.g. `channel-4`). Empty = any.
    pub allowed_ics20_channels: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            chain_id: String::new(),
            allowed_actions: ["spend", "output", "ics20_withdrawal", "position_open", "position_close", "position_withdraw"]
                .map(String::from)
                .to_vec(),
            allowed_output_addresses: vec![],
            allowed_ics20_receivers: vec![],
            allowed_ics20_channels: vec![],
        }
    }
}

impl Policy {
    /// Everything a cold wallet does day to day (opt-in beyond the default):
    /// transfers, ICS20 out, LP, swaps, staking. No governance/validator actions.
    pub fn wallet_template(chain_id: &str, allowed_outputs: Vec<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            allowed_actions: [
                "spend", "output", "ics20_withdrawal", "position_open", "position_close", "position_withdraw",
                "swap", "swap_claim", "delegate", "undelegate", "undelegate_claim",
            ]
            .map(String::from)
            .to_vec(),
            allowed_output_addresses: allowed_outputs,
            allowed_ics20_receivers: vec![],
            allowed_ics20_channels: vec![],
        }
    }

    pub fn check(&self, plan: &TransactionPlan, fvk: &FullViewingKey) -> Result<()> {
        if !self.chain_id.is_empty() && plan.transaction_parameters.chain_id != self.chain_id {
            bail!("plan is for chain {:?}, policy expects {:?}", plan.transaction_parameters.chain_id, self.chain_id);
        }
        let extra: Vec<Address> = self.allowed_output_addresses.iter().filter_map(|a| Address::from_str(a).ok()).collect();
        for a in &plan.actions {
            let k = kind(a);
            if !self.allowed_actions.iter().any(|x| x == k) {
                bail!("policy refuses action {k}");
            }
            match a {
                ActionPlan::Spend(s) => {
                    if fvk.address_index(&s.note.address()).is_none() {
                        bail!("spend of a note not owned by the pinned account");
                    }
                }
                ActionPlan::Output(o) => {
                    if fvk.address_index(&o.dest_address).is_none() && !extra.contains(&o.dest_address) {
                        bail!("output to non-allow-listed address {}", o.dest_address);
                    }
                }
                ActionPlan::Ics20Withdrawal(w) => {
                    // chain rule (Ics20Withdrawal::validate): timeout rounded to the minute
                    if w.timeout_time % 60_000_000_000 != 0 {
                        bail!("ics20 timeout_time must be rounded to a minute");
                    }
                    if fvk.address_index(&w.return_address).is_none() {
                        bail!("ics20 return address is not ours");
                    }
                    if !self.allowed_ics20_receivers.is_empty() && !self.allowed_ics20_receivers.contains(&w.destination_chain_address) {
                        bail!("ics20 receiver {} not allow-listed", w.destination_chain_address);
                    }
                    let ch = w.source_channel.to_string();
                    if !self.allowed_ics20_channels.is_empty() && !self.allowed_ics20_channels.contains(&ch) {
                        bail!("ics20 channel {ch} not allow-listed");
                    }
                }
                ActionPlan::Swap(sw) => {
                    if fvk.address_index(&sw.swap_plaintext.claim_address).is_none() {
                        bail!("swap claim address is not ours");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
