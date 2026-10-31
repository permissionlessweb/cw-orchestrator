//! Authorization policy checks shared by grant/approval/terminal.
//! Pure functions only; nothing here touches disk or the network.

use rand::RngCore;

pub const MAX_SESSION_TTL_SECS: u64 = 86_400;
/// An operator grant covers the study, not one sitting. Thirty days.
pub const MAX_OPERATOR_GRANT_TTL_SECS: u64 = 30 * 86_400;
pub const MAX_CALLS_PER_CONTRACT: u64 = 1_000;
pub const MAX_CHALLENGE_TTL_SECS: u64 = 900;
pub const GRANTER_CHALLENGE_PREFIX: &str = "cw-orch-granter:v2";

/// Message types a scripted session must never be granted.
pub const FORBIDDEN_SESSION_URLS: &[&str] = &[
    "/cosmos.authz.v1beta1.MsgGrant",
    "/cosmos.authz.v1beta1.MsgExec",
    "/cosmos.authz.v1beta1.MsgRevoke",
    "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
    "/cosmos.feegrant.v1beta1.MsgRevokeAllowance",
    "/cosmos.bank.v1beta1.MsgSend",
    "/cosmos.bank.v1beta1.MsgMultiSend",
    "/cosmos.staking.v1beta1.MsgDelegate",
    "/cosmos.staking.v1beta1.MsgUndelegate",
    "/cosmos.staking.v1beta1.MsgBeginRedelegate",
    "/cosmos.staking.v1beta1.MsgCreateValidator",
    "/cosmos.staking.v1beta1.MsgEditValidator",
    "/cosmos.distribution.v1beta1.MsgSetWithdrawAddress",
    "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward",
    "/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission",
    "/cosmos.slashing.v1beta1.MsgUnjail",
    "/cosmwasm.wasm.v1.MsgUpdateAdmin",
    "/cosmwasm.wasm.v1.MsgClearAdmin",
    "/cosmwasm.wasm.v1.MsgUpdateInstantiateConfig",
    "/ibc.applications.transfer.v1.MsgTransfer",
];

pub fn refuse_forbidden(type_url: &str) -> Result<(), String> {
    if FORBIDDEN_SESSION_URLS.contains(&type_url) {
        return Err(format!("{type_url} may not be granted to a script session"));
    }
    Ok(())
}

pub fn validate_ttl(ttl_secs: u64) -> Result<(), String> {
    validate_ttl_max(ttl_secs, MAX_SESSION_TTL_SECS, "session")
}

pub fn validate_operator_grant_ttl(ttl_secs: u64) -> Result<(), String> {
    validate_ttl_max(ttl_secs, MAX_OPERATOR_GRANT_TTL_SECS, "operator grant")
}

fn validate_ttl_max(ttl_secs: u64, max: u64, kind: &str) -> Result<(), String> {
    if ttl_secs == 0 {
        return Err(format!("{kind} ttl must be > 0"));
    }
    if ttl_secs > max {
        return Err(format!("{kind} ttl {ttl_secs}s exceeds max {max}s"));
    }
    Ok(())
}

pub fn validate_expiration(expires_unix: u64, now: u64) -> Result<(), String> {
    if expires_unix <= now {
        return Err("grant expiration is in the past".into());
    }
    validate_ttl(expires_unix - now)
}

pub fn validate_calls(contract: &str, calls: u64) -> Result<(), String> {
    if contract.trim().is_empty() {
        return Err("scoped call has no contract".into());
    }
    if calls == 0 || calls > MAX_CALLS_PER_CONTRACT {
        return Err(format!(
            "calls for {contract} must be 1..={MAX_CALLS_PER_CONTRACT}, got {calls}"
        ));
    }
    Ok(())
}

pub fn validate_allowance(amount: u128) -> Result<(), String> {
    if amount == 0 {
        return Err("fee allowance spend limit must be > 0".into());
    }
    Ok(())
}

pub fn ensure_chain_id(configured: &str, reported: &str) -> Result<(), String> {
    if configured.is_empty() || reported.is_empty() {
        return Err("chain-id missing".into());
    }
    if configured != reported {
        return Err(format!(
            "chain-id mismatch: configured {configured}, node reports {reported}"
        ));
    }
    Ok(())
}

pub fn validate_terp_address(addr: &str) -> Result<(), String> {
    crate::chain::validate_address(addr, "terp")
}

/// Address check against the configured approval chain's prefix.
pub fn validate_chain_address(addr: &str) -> Result<(), String> {
    crate::chain::validate_address(addr, &crate::chain::approval_chain().bech32_prefix)
}

/// Escalation messages refused even for explicit wallet catalogs: they hand out
/// authority or move contract admin.
pub const ESCALATION_URLS: &[&str] = &[
    "/cosmos.authz.v1beta1.MsgGrant",
    "/cosmos.authz.v1beta1.MsgExec",
    "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
    "/cosmwasm.wasm.v1.MsgUpdateAdmin",
    "/cosmwasm.wasm.v1.MsgClearAdmin",
    "/cosmwasm.wasm.v1.MsgUpdateInstantiateConfig",
];

pub fn refuse_escalation(type_url: &str) -> Result<(), String> {
    if ESCALATION_URLS.contains(&type_url) {
        return Err(format!("{type_url} is an escalation and is never granted"));
    }
    Ok(())
}

/// When the principal is a terp address the approving signer must be exactly it.
/// A non-address principal is a label (e.g. "treasury") and binds by signature only.
pub fn principal_accepts(principal: Option<&str>, signer: &str) -> bool {
    match principal {
        Some(p) if p.is_empty() => false,
        Some(p) if validate_chain_address(p).is_ok() => p == signer,
        _ => true,
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GranterChallenge {
    pub purpose: String,
    pub chain_id: String,
    pub nonce_hex: String,
    pub expires_unix: u64,
}

impl GranterChallenge {
    pub fn new(purpose: &str, chain_id: &str, ttl_secs: u64, now: u64) -> Result<Self, String> {
        if purpose.trim().is_empty() {
            return Err("challenge purpose is empty".into());
        }
        if purpose.chars().any(|c| c.is_control()) || chain_id.chars().any(|c| c.is_control() || c == ' ') {
            return Err("challenge purpose/chain-id must be one line".into());
        }
        if chain_id.trim().is_empty() {
            return Err("challenge chain-id is empty".into());
        }
        if ttl_secs == 0 || ttl_secs > MAX_CHALLENGE_TTL_SECS {
            return Err(format!("challenge ttl must be 1..={MAX_CHALLENGE_TTL_SECS}"));
        }
        let mut n = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut n);
        let nonce_hex = n.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            purpose: purpose.into(),
            chain_id: chain_id.into(),
            nonce_hex,
            expires_unix: now + ttl_secs,
        })
    }

    /// One line: Zigner's `granter_binding` refuses a binding with a newline
    /// or control character. Purpose goes last so spaces in it are harmless.
    pub fn binding(&self) -> String {
        format!(
            "{GRANTER_CHALLENGE_PREFIX} chain-id={} nonce={} expires={} purpose={}",
            self.chain_id, self.nonce_hex, self.expires_unix, self.purpose
        )
    }

    /// The exact bytes the cold key signs (see `terminal::capture_granter`).
    pub fn document(&self) -> String {
        format!("cw-orch-granter:v1\n{}", self.binding())
    }

    /// Checks a signed document is exactly this challenge, for this chain, unexpired.
    pub fn validate(&self, signed_doc: &str, chain_id: &str, now: u64) -> Result<(), String> {
        ensure_chain_id(&self.chain_id, chain_id)?;
        if now >= self.expires_unix {
            return Err("granter challenge expired".into());
        }
        if signed_doc != self.document() {
            return Err("signed document does not match challenge".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_urls_refused() {
        assert!(refuse_forbidden("/cosmos.authz.v1beta1.MsgExec").is_err());
        assert!(refuse_forbidden("/cosmos.bank.v1beta1.MsgSend").is_err());
        assert!(refuse_forbidden("/cosmwasm.wasm.v1.MsgUpdateAdmin").is_err());
        assert!(refuse_forbidden("/cosmwasm.wasm.v1.MsgExecuteContract").is_ok());
    }

    #[test]
    fn ttl_bounds() {
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(MAX_SESSION_TTL_SECS + 1).is_err());
        assert!(validate_ttl(7200).is_ok());
        assert!(validate_expiration(100, 100).is_err());
        assert!(validate_expiration(200, 100).is_ok());
    }

    #[test]
    fn calls_and_allowance() {
        assert!(validate_calls("", 1).is_err());
        assert!(validate_calls("terp1x", 0).is_err());
        assert!(validate_calls("terp1x", MAX_CALLS_PER_CONTRACT + 1).is_err());
        assert!(validate_calls("terp1x", 5).is_ok());
        assert!(validate_allowance(0).is_err());
        assert!(validate_allowance(1).is_ok());
    }

    #[test]
    fn chain_id_mismatch_refused() {
        assert!(ensure_chain_id("morocco-1", "morocco-1").is_ok());
        assert!(ensure_chain_id("morocco-1", "terp-1").is_err());
        assert!(ensure_chain_id("", "").is_err());
    }

    #[test]
    fn terp_addresses() {
        let enc = |hrp: &str, n: usize| {
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse(hrp).unwrap(), &vec![7u8; n]).unwrap()
        };
        assert!(validate_terp_address(&enc("terp", 20)).is_ok());
        assert!(validate_terp_address(&enc("terp", 32)).is_ok());
        assert!(validate_terp_address(&enc("terp", 19)).is_err());
        assert!(validate_terp_address(&enc("cosmos", 20)).is_err());
        assert!(validate_terp_address("garbage").is_err());
    }

    #[test]
    fn principal_binding() {
        let enc = |b: u8| {
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("terp").unwrap(), &[b; 20]).unwrap()
        };
        let (a, b) = (enc(1), enc(2));
        assert!(principal_accepts(Some(&a), &a));
        assert!(!principal_accepts(Some(&a), &b));
        assert!(!principal_accepts(Some(""), &b));
        assert!(principal_accepts(Some("treasury"), &b));
        assert!(principal_accepts(None, &b));
        assert!(refuse_escalation("/cosmwasm.wasm.v1.MsgUpdateAdmin").is_err());
        assert!(refuse_escalation("/cosmos.bank.v1beta1.MsgSend").is_ok());
    }

    #[test]
    fn challenge_binds_chain_nonce_expiry() {
        let c = GranterChallenge::new("bounty-dao", "morocco-1", 300, 1000).unwrap();
        let d = c.document();
        assert!(d.starts_with("cw-orch-granter:v1\ncw-orch-granter:v2 "));
        assert_eq!(d.matches('\n').count(), 1);
        assert!(GranterChallenge::new("a\nb", "m", 300, 0).is_err());
        assert!(d.contains("chain-id=morocco-1"));
        assert_eq!(c.nonce_hex.len(), 32);
        assert!(c.validate(&d, "morocco-1", 1100).is_ok());
        assert!(c.validate(&d, "terp-1", 1100).is_err());
        assert!(c.validate(&d, "morocco-1", 1300).is_err());
        assert!(c.validate("cw-orch-granter:v1\napp-setup", "morocco-1", 1100).is_err());
        let c2 = GranterChallenge::new("bounty-dao", "morocco-1", 300, 1000).unwrap();
        assert_ne!(c.nonce_hex, c2.nonce_hex);
        assert!(GranterChallenge::new("x", "", 300, 0).is_err());
        assert!(GranterChallenge::new("x", "m", MAX_CHALLENGE_TTL_SECS + 1, 0).is_err());
    }
}
