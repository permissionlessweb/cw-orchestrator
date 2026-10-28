//! Zigner's response and its verification.
//!
//! Zigner (`transaction_signing::penumbra::PenumbraAuthorizationData::encode`)
//! answers with, and shows as a QR of the ASCII **hex** of:
//!
//! ```text
//! effect_hash [64]
//! spend_count u16 LE | spend_auth sigs [64]*
//! vote_count  u16 LE | delegator_vote sigs [64]*
//! lqt_count   u16 LE | lqt_vote sigs [64]*
//! ```
//!
//! Nothing here is trusted: we recompute the effect hash from the plan with the
//! pinned FVK and check every signature against
//! `fvk.spend_verification_key().randomize(randomizer)` — exactly what the
//! chain will check (`rk` is part of each spend body).

use anyhow::{bail, ensure, Context, Result};
use decaf377_rdsa::{Signature, SpendAuth};
use penumbra_sdk_keys::FullViewingKey;
use penumbra_sdk_transaction::{AuthorizationData, TransactionPlan};
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZignerResponse {
    pub effect_hash: [u8; 64],
    pub spend_auths: Vec<[u8; 64]>,
    pub delegator_vote_auths: Vec<[u8; 64]>,
    pub lqt_vote_auths: Vec<[u8; 64]>,
}

impl ZignerResponse {
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= 64 + 6, "response too short");
        let effect_hash: [u8; 64] = b[..64].try_into()?;
        let mut i = 64;
        let mut lists = vec![];
        for _ in 0..3 {
            ensure!(i + 2 <= b.len(), "truncated response");
            let n = u16::from_le_bytes([b[i], b[i + 1]]) as usize;
            i += 2;
            ensure!(i + 64 * n <= b.len(), "truncated response");
            lists.push((0..n).map(|k| b[i + 64 * k..i + 64 * (k + 1)].try_into().unwrap()).collect::<Vec<[u8; 64]>>());
            i += 64 * n;
        }
        ensure!(i == b.len(), "trailing bytes in response");
        let lqt = lists.pop().unwrap();
        let votes = lists.pop().unwrap();
        let spends = lists.pop().unwrap();
        Ok(Self { effect_hash, spend_auths: spends, delegator_vote_auths: votes, lqt_vote_auths: lqt })
    }

    /// Accepts what a QR scanner / the paste box gives: hex text (any case,
    /// whitespace ignored, optional `0x`), or — if the scanner already decoded
    /// it — raw bytes.
    pub fn decode_text_or_bytes(b: &[u8]) -> Result<Self> {
        let s: String = String::from_utf8_lossy(b).chars().filter(|c| !c.is_whitespace()).collect();
        let s = s.strip_prefix("0x").unwrap_or(&s);
        if !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Self::decode(&hex::decode(s)?);
        }
        Self::decode(b)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.effect_hash.to_vec();
        for l in [&self.spend_auths, &self.delegator_vote_auths, &self.lqt_vote_auths] {
            out.extend_from_slice(&(l.len() as u16).to_le_bytes());
            for s in l.iter() {
                out.extend_from_slice(s);
            }
        }
        out
    }
}

/// Verify Zigner's answer for `plan` under the pinned `fvk` and turn it into
/// [`AuthorizationData`] (what `CustodyService.Authorize` returns and what
/// `TransactionPlan::build` / `WitnessData` consumes).
pub fn verify_response(plan: &TransactionPlan, fvk: &FullViewingKey, resp: &ZignerResponse) -> Result<AuthorizationData> {
    let eh = plan.effect_hash(fvk).context("computing effect hash")?;
    if !bool::from(eh.as_bytes().ct_eq(&resp.effect_hash)) {
        bail!("effect hash mismatch: the phone signed a different transaction (or holds a different account)");
    }
    let spends: Vec<_> = plan.spend_plans().collect();
    let votes: Vec<_> = plan.delegator_vote_plans().collect();
    let lqts: Vec<_> = plan.lqt_vote_plans().collect();
    ensure!(resp.spend_auths.len() == spends.len(), "expected {} spend signatures, got {}", spends.len(), resp.spend_auths.len());
    ensure!(resp.delegator_vote_auths.len() == votes.len(), "delegator vote signature count mismatch");
    ensure!(resp.lqt_vote_auths.len() == lqts.len(), "lqt vote signature count mismatch");

    let ak = fvk.spend_verification_key();
    let check = |r: &decaf377::Fr, sig: &[u8; 64], what: &str, i: usize| -> Result<Signature<SpendAuth>> {
        let sig = Signature::<SpendAuth>::from(*sig);
        ak.randomize(r)
            .verify(eh.as_bytes(), &sig)
            .map_err(|_| anyhow::anyhow!("{what} signature {i} does not verify against the pinned account"))?;
        Ok(sig)
    };
    let spend_auths = spends.iter().zip(&resp.spend_auths).enumerate().map(|(i, (p, s))| check(&p.randomizer, s, "spend", i)).collect::<Result<_>>()?;
    let delegator_vote_auths = votes.iter().zip(&resp.delegator_vote_auths).enumerate().map(|(i, (p, s))| check(&p.randomizer, s, "delegator vote", i)).collect::<Result<_>>()?;
    let lqt_vote_auths = lqts.iter().zip(&resp.lqt_vote_auths).enumerate().map(|(i, (p, s))| check(&p.randomizer, s, "lqt vote", i)).collect::<Result<_>>()?;

    Ok(AuthorizationData { effect_hash: Some(eh), spend_auths, delegator_vote_auths, lqt_vote_auths })
}
