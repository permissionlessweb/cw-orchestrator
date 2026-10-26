//! Per-chain settings for the cold-key flow: bech32 prefix, chain-id, fee
//! denom, gas price, coin type and the Zigner `chain_name` written on the QR.
//! The default stays Terp (`terp` / `morocco-1` / `uthiol`) so callers that
//! never pick a chain behave exactly as before.

use std::sync::RwLock;

#[derive(Clone, Debug, PartialEq)]
pub struct ChainProfile {
    pub chain_id: String,
    pub bech32_prefix: String,
    pub fee_denom: String,
    pub gas_price: f64,
    /// SLIP-44 coin type. 118 unless the chain says otherwise.
    pub coin_type: u32,
    /// `chain_name` on the Zigner QR. Zigner maps it to a prefix; names it
    /// does not know fall back to `cosmos` (see the Zigner prefix fix).
    pub zigner_chain_name: String,
    /// Human label for page text ("Terp key", "Osmosis key").
    pub display_name: String,
}

pub const DEFAULT_COIN_TYPE: u32 = 118;

impl ChainProfile {
    pub fn new(
        chain_id: impl Into<String>,
        bech32_prefix: impl Into<String>,
        fee_denom: impl Into<String>,
        gas_price: f64,
        zigner_chain_name: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            bech32_prefix: bech32_prefix.into(),
            fee_denom: fee_denom.into(),
            gas_price,
            coin_type: DEFAULT_COIN_TYPE,
            zigner_chain_name: zigner_chain_name.into(),
            display_name: display_name.into(),
        }
    }
    pub fn with_coin_type(mut self, coin_type: u32) -> Self {
        self.coin_type = coin_type;
        self
    }
    pub fn terp() -> Self {
        Self::new("morocco-1", "terp", "uthiol", 0.05, "terp", "Terp")
    }
    pub fn osmosis() -> Self {
        Self::new("osmosis-1", "osmo", "uosmo", 0.025, "osmosis", "Osmosis")
    }
    pub fn juno() -> Self {
        Self::new("juno-1", "juno", "ujuno", 0.075, "juno", "Juno")
    }
    pub fn atomone() -> Self {
        Self::new("atomone-1", "atone", "uatone", 0.025, "atomone", "AtomOne")
    }
    pub fn presets() -> Vec<Self> {
        vec![Self::terp(), Self::osmosis(), Self::juno(), Self::atomone()]
    }
    /// Known preset for a chain-id. Terp testnets/local ids resolve by prefix.
    pub fn for_chain_id(chain_id: &str) -> Option<Self> {
        Self::presets().into_iter().find(|p| p.chain_id == chain_id)
    }
    pub fn for_prefix(prefix: &str) -> Option<Self> {
        Self::presets().into_iter().find(|p| p.bech32_prefix == prefix)
    }
    /// Same chain settings under another chain-id (testnet, localnet).
    pub fn on_chain_id(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = chain_id.into();
        self
    }
    pub fn validate(&self) -> Result<(), String> {
        bech32::Hrp::parse(&self.bech32_prefix)
            .map_err(|e| format!("chain profile: bad prefix {:?}: {e}", self.bech32_prefix))?;
        if self.chain_id.trim().is_empty() || self.fee_denom.trim().is_empty() {
            return Err("chain profile: empty chain-id or fee denom".into());
        }
        if self.zigner_chain_name.is_empty() || self.zigner_chain_name.len() > 255 {
            return Err("chain profile: bad zigner chain_name".into());
        }
        if !self.gas_price.is_finite() || self.gas_price < 0.0 {
            return Err("chain profile: bad gas price".into());
        }
        Ok(())
    }
    pub fn address(&self, hash20: &[u8]) -> Option<String> {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse(&self.bech32_prefix).ok()?, hash20).ok()
    }
}

impl Default for ChainProfile {
    fn default() -> Self {
        Self::terp()
    }
}

static APPROVAL_CHAIN: RwLock<Option<ChainProfile>> = RwLock::new(None);

/// Pick the chain for the approval pages. Also sets the approval chain-id the
/// v2 challenge and approval sign bytes bind to.
pub fn set_approval_chain(profile: ChainProfile) -> Result<(), String> {
    profile.validate()?;
    crate::terminal::set_approval_chain_id(&profile.chain_id)?;
    *APPROVAL_CHAIN.write().map_err(|_| "approval refused: chain lock".to_string())? = Some(profile);
    Ok(())
}

/// The chain in use: an explicit profile whose chain-id matches the approval
/// chain-id, else a preset for that chain-id, else Terp.
pub fn approval_chain() -> ChainProfile {
    let id = crate::terminal::approval_chain_id().ok();
    if let Some(p) = APPROVAL_CHAIN.read().ok().and_then(|g| g.clone()) {
        if id.as_deref().map_or(true, |id| id == p.chain_id) {
            return p;
        }
    }
    id.as_deref().and_then(ChainProfile::for_chain_id).unwrap_or_default()
}

/// Drop any explicit chain (tests).
pub fn clear_approval_chain() {
    if let Ok(mut g) = APPROVAL_CHAIN.write() {
        *g = None;
    }
}

pub fn validate_address(addr: &str, prefix: &str) -> Result<(), String> {
    let (hrp, data) = bech32::decode(addr).map_err(|e| format!("bad address {addr}: {e}"))?;
    if hrp.as_str() != prefix {
        return Err(format!("address {addr} is not a {prefix} address"));
    }
    if data.len() != 20 && data.len() != 32 {
        return Err(format!("address {addr} has bad length {}", data.len()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(hrp: &str, n: usize) -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse(hrp).unwrap(), &vec![7u8; n]).unwrap()
    }

    #[test]
    fn default_is_terp() {
        let p = ChainProfile::default();
        assert_eq!((p.bech32_prefix.as_str(), p.chain_id.as_str(), p.fee_denom.as_str()), ("terp", "morocco-1", "uthiol"));
        assert_eq!(p.coin_type, 118);
        assert_eq!(p.zigner_chain_name, "terp");
    }

    #[test]
    fn presets_validate() {
        for p in ChainProfile::presets() {
            p.validate().unwrap();
        }
        assert!(ChainProfile::new("x-1", "BAD PREFIX", "u", 0.1, "x", "X").validate().is_err());
    }

    #[test]
    fn osmo_prefix() {
        let p = ChainProfile::osmosis();
        assert!(validate_address(&enc("osmo", 20), &p.bech32_prefix).is_ok());
        assert!(validate_address(&enc("terp", 20), &p.bech32_prefix).is_err());
        assert_eq!(ChainProfile::for_chain_id("osmosis-1").unwrap().fee_denom, "uosmo");
        assert!(p.address(&[1u8; 20]).unwrap().starts_with("osmo1"));
    }

    #[test]
    fn juno_prefix() {
        let p = ChainProfile::juno();
        assert!(validate_address(&enc("juno", 20), &p.bech32_prefix).is_ok());
        assert!(validate_address(&enc("juno", 32), &p.bech32_prefix).is_ok());
        assert!(validate_address(&enc("osmo", 20), &p.bech32_prefix).is_err());
        assert_eq!(ChainProfile::for_prefix("juno").unwrap().chain_id, "juno-1");
    }

    #[test]
    fn atone_prefix() {
        let p = ChainProfile::atomone();
        assert!(validate_address(&enc("atone", 20), &p.bech32_prefix).is_ok());
        assert!(validate_address(&enc("atone", 19), &p.bech32_prefix).is_err());
        assert!(validate_address(&enc("cosmos", 20), &p.bech32_prefix).is_err());
        assert_eq!(ChainProfile::for_chain_id("atomone-1").unwrap().fee_denom, "uatone");
    }
}
