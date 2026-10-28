//! Human-readable plan summary for the approval page (and the terminal).
//! Built from the plan we will verify against, never from the phone.

use penumbra_sdk_asset::{asset::Cache, Value};
use penumbra_sdk_keys::{Address, FullViewingKey};
use penumbra_sdk_transaction::{ActionPlan, TransactionPlan};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    pub chain_id: String,
    pub expiry_height: u64,
    pub fee: String,
    pub effect_hash: String,
    pub actions: Vec<String>,
    /// Lines that deserve a second look (value leaving the pinned account).
    pub warnings: Vec<String>,
}

fn short(a: &Address) -> String {
    let s = a.to_string();
    if s.len() > 40 { format!("{}…{}", &s[..24], &s[s.len() - 10..]) } else { s }
}

fn who(fvk: &FullViewingKey, a: &Address) -> String {
    match fvk.address_index(a) {
        Some(ix) => format!("own account {}", ix.account),
        None => format!("EXTERNAL {}", short(a)),
    }
}

pub fn fmt_value(v: &Value, cache: &Cache) -> String {
    v.format(cache)
}

pub fn summarize(plan: &TransactionPlan, fvk: &FullViewingKey) -> Summary {
    let cache = Cache::with_known_assets();
    let mut actions = vec![];
    let mut warnings = vec![];
    for a in &plan.actions {
        let line = match a {
            ActionPlan::Spend(s) => format!("spend {} (note of {})", fmt_value(&s.note.value(), &cache), who(fvk, &s.note.address())),
            ActionPlan::Output(o) => {
                let l = format!("output {} → {}", fmt_value(&o.value, &cache), who(fvk, &o.dest_address));
                if fvk.address_index(&o.dest_address).is_none() {
                    warnings.push(format!("sends {} to {}", fmt_value(&o.value, &cache), o.dest_address));
                }
                l
            }
            ActionPlan::Ics20Withdrawal(w) => {
                let v = fmt_value(&w.value(), &cache);
                warnings.push(format!("IBC transfer {} to {} via {}", v, w.destination_chain_address, w.source_channel));
                format!(
                    "ICS20 transfer out {} via {} → {} (timeout height {}, time {}, return {}{})",
                    v,
                    w.source_channel,
                    w.destination_chain_address,
                    w.timeout_height,
                    w.timeout_time,
                    who(fvk, &w.return_address),
                    if w.ics20_memo.is_empty() { String::new() } else { format!(", memo {:?}", w.ics20_memo) }
                )
            }
            ActionPlan::PositionOpen(p) => {
                let pos = &p.position;
                let pair = &pos.phi.pair;
                format!(
                    "LP open {} : reserves {} + {}, fee {} bps, p={} q={}",
                    pos.id(),
                    fmt_value(&Value { amount: pos.reserves.r1, asset_id: pair.asset_1() }, &cache),
                    fmt_value(&Value { amount: pos.reserves.r2, asset_id: pair.asset_2() }, &cache),
                    pos.phi.component.fee,
                    pos.phi.component.p,
                    pos.phi.component.q,
                )
            }
            ActionPlan::PositionClose(c) => format!("LP close {}", c.position_id),
            ActionPlan::PositionWithdraw(w) => format!(
                "LP withdraw {} (seq {}): {} + {}",
                w.position_id,
                w.sequence,
                fmt_value(&Value { amount: w.reserves.r1, asset_id: w.pair.asset_1() }, &cache),
                fmt_value(&Value { amount: w.reserves.r2, asset_id: w.pair.asset_2() }, &cache),
            ),
            other => {
                let l = format!("other action: {}", super::policy::kind(other));
                warnings.push(l.clone());
                l
            }
        };
        actions.push(line);
    }
    if plan.memo.is_some() {
        actions.push("encrypted memo attached".into());
    }
    Summary {
        chain_id: plan.transaction_parameters.chain_id.clone(),
        expiry_height: plan.transaction_parameters.expiry_height,
        fee: fmt_value(&plan.transaction_parameters.fee.0, &cache),
        effect_hash: plan.effect_hash(fvk).map(|h| hex::encode(h.as_bytes())).unwrap_or_else(|e| format!("error: {e}")),
        actions,
        warnings,
    }
}

impl Summary {
    pub fn to_text(&self) -> String {
        let mut s = format!("chain {}  expiry {}  fee {}\n", self.chain_id, self.expiry_height, self.fee);
        for a in &self.actions {
            s += &format!("  - {a}\n");
        }
        for w in &self.warnings {
            s += &format!("  ! {w}\n");
        }
        s += &format!("effect hash {}\n", self.effect_hash);
        s
    }
}
