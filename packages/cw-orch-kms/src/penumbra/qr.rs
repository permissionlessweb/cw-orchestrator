//! Zigner's Penumbra sign request (`53 03 10`), byte for byte as
//! `transaction_parsing::penumbra::parse_penumbra_transaction` reads it:
//!
//! ```text
//! 53 03 10
//! chain_id_len u8 (8..=50) | chain_id
//! asset_count u8 | (name_len u8 | name)*
//! plan_len u32 LE | TransactionPlan proto
//! effect_hash [64]
//! spend_count u16 LE | spend randomizers [32]*   (Fr, little-endian)
//! vote_count  u16 LE | delegator-vote randomizers [32]*
//! lqt_count   u16 LE | lqt-vote randomizers [32]*
//! ```
//!
//! Zigner re-decodes the plan, recomputes the effect hash with its own FVK and
//! refuses to sign on mismatch, so the hash we put here is only a hint; what it
//! signs is what the plan says. Frames and QR rendering are the shared
//! [`crate::ui_shared::zigner_frames`] / [`crate::ui_shared::raptor_frames`].

use anyhow::{bail, ensure, Context, Result};
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_proto::DomainType;
use penumbra_sdk_transaction::TransactionPlan;

pub const PRELUDE: [u8; 3] = [0x53, 0x03, 0x10];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZignerRequest {
    pub chain_id: String,
    pub asset_names: Vec<String>,
    pub plan_bytes: Vec<u8>,
    pub effect_hash: [u8; 64],
    pub spend_randomizers: Vec<[u8; 32]>,
    pub delegator_vote_randomizers: Vec<[u8; 32]>,
    pub lqt_vote_randomizers: Vec<[u8; 32]>,
}

impl ZignerRequest {
    pub fn from_plan(plan: &TransactionPlan, fvk: &FullViewingKey, asset_names: Vec<String>) -> Result<Self> {
        let effect_hash = plan.effect_hash(fvk).context("computing effect hash")?;
        Ok(Self {
            chain_id: plan.transaction_parameters.chain_id.clone(),
            asset_names,
            plan_bytes: plan.encode_to_vec(),
            effect_hash: *effect_hash.as_bytes(),
            spend_randomizers: plan.spend_plans().map(|p| p.randomizer.to_bytes()).collect(),
            delegator_vote_randomizers: plan.delegator_vote_plans().map(|p| p.randomizer.to_bytes()).collect(),
            lqt_vote_randomizers: plan.lqt_vote_plans().map(|p| p.randomizer.to_bytes()).collect(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let cid = self.chain_id.as_bytes();
        // Zigner tells the Penumbra format apart by this length byte.
        ensure!((8..=50).contains(&cid.len()), "chain id must be 8..=50 bytes for Zigner, got {}", cid.len());
        ensure!(self.asset_names.len() <= 255, "too many asset names");
        let mut out = Vec::with_capacity(3 + 64 + self.plan_bytes.len() + 128);
        out.extend_from_slice(&PRELUDE);
        out.push(cid.len() as u8);
        out.extend_from_slice(cid);
        out.push(self.asset_names.len() as u8);
        for n in &self.asset_names {
            ensure!(n.len() <= 255, "asset name too long");
            out.push(n.len() as u8);
            out.extend_from_slice(n.as_bytes());
        }
        out.extend_from_slice(&(self.plan_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.plan_bytes);
        out.extend_from_slice(&self.effect_hash);
        for list in [&self.spend_randomizers, &self.delegator_vote_randomizers, &self.lqt_vote_randomizers] {
            ensure!(list.len() <= u16::MAX as usize, "too many randomizers");
            out.extend_from_slice(&(list.len() as u16).to_le_bytes());
            for r in list.iter() {
                out.extend_from_slice(r);
            }
        }
        Ok(out)
    }

    /// Inverse of [`encode`](Self::encode) (used by tests and the device
    /// simulator; mirrors Zigner's parser, including its bounds).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut c = Cursor { b, i: 0 };
        if c.take(3)? != PRELUDE {
            bail!("not a Zigner penumbra request");
        }
        let n = c.u8()? as usize;
        ensure!((8..=50).contains(&n), "bad chain id length");
        let chain_id = String::from_utf8(c.take(n)?.to_vec())?;
        let mut asset_names = vec![];
        for _ in 0..c.u8()? {
            let l = c.u8()? as usize;
            asset_names.push(String::from_utf8(c.take(l)?.to_vec())?);
        }
        let pl = u32::from_le_bytes(c.take(4)?.try_into()?) as usize;
        let plan_bytes = c.take(pl)?.to_vec();
        let effect_hash: [u8; 64] = c.take(64)?.try_into()?;
        let mut lists = vec![];
        for _ in 0..3 {
            let k = u16::from_le_bytes(c.take(2)?.try_into()?) as usize;
            let mut v = vec![];
            for _ in 0..k {
                v.push(<[u8; 32]>::try_from(c.take(32)?)?);
            }
            lists.push(v);
        }
        let lqt = lists.pop().unwrap();
        let votes = lists.pop().unwrap();
        let spends = lists.pop().unwrap();
        Ok(Self {
            chain_id,
            asset_names,
            plan_bytes,
            effect_hash,
            spend_randomizers: spends,
            delegator_vote_randomizers: votes,
            lqt_vote_randomizers: lqt,
        })
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.i + n <= self.b.len(), "truncated request");
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
}
