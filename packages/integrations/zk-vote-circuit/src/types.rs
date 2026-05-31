//! Circuit type definition, trait implementations, and upload plumbing.
//!
//! Defines [`ZkVoteCircuit`] — the main entry point that ties together
//! the voter identity, Merkle tree, and proof logic into a single
//! [`CircuitInstance`] / [`CircuitUploadable`] / [`CircuitFooterSpec`]
//! implementation consumable by cw-orchestrator.

use cw_orch_core::{
    contract::circuits::{
        circuit_interface_traits::{CircuitInstance, CircuitUploadable},
        Circuit,
    },
    environment::ChainState,
};

use serde::{Deserialize, Serialize};

// ── ZkVoteCircuit ─────────────────────────────────────────────────────────────

/// A cw-orchestrator circuit representing the ZK voting application.
///
/// Wraps a [`Circuit<Chain>`] and implements [`CircuitInstance`],
/// [`CircuitUploadable`], and [`CircuitFooterSpec`] so it can be uploaded,
/// queried, and verified through the standard cw-orch circuit pipeline.
///
/// # Type parameters
/// - `Chain`: a chain/environment that implements [`ChainState`]. Must also
///   implement [`cw_orch_core::environment::ZkTxHandler`] for upload operations.
#[derive(Clone)]
pub struct ZkVoteCircuit<Chain> {
    inner: Circuit<Chain>,
}

impl<Chain> ZkVoteCircuit<Chain> {
    /// Create a new `ZkVoteCircuit` wrapping the given `Circuit`.
    pub fn new(id: impl ToString, chain: Chain) -> Self {
        Self {
            inner: Circuit::new(id, chain),
        }
    }
}

// ── CircuitInstance impl ──────────────────────────────────────────────────────

impl<Chain: ChainState> CircuitInstance<Chain> for ZkVoteCircuit<Chain> {
    fn as_circuit(&self) -> &Circuit<Chain> {
        &self.inner
    }

    fn as_circuit_mut(&mut self) -> &mut Circuit<Chain> {
        &mut self.inner
    }
}

// ── CircuitUploadable impl ────────────────────────────────────────────────────

/// Phantom placeholder used in [`CircuitUploadable`] and [`CircuitFooterSpec`]
/// impls where the concrete chain type is not yet known.
pub type NeedsChain = ();

impl<Chain> CircuitUploadable for ZkVoteCircuit<Chain> {
    fn circuit_name() -> String {
        "zk_vote".to_string()
    }

    fn circuit_path(_chain: &cw_orch_core::environment::ChainInfoOwned) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from("circuit_keys");
        path.push("zk_vote");
        path.push("zk_vote_plonkish.bin");
        path
    }

    fn vk_combined_path(_chain: &cw_orch_core::environment::ChainInfoOwned) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from("circuit_keys");
        path.push("zk_vote");
        path.push("vk_combined.bin");
        path
    }
}

// ── CircuitFooterSpec impl ────────────────────────────────────────────────────

use cw_orch_core::contract::circuits::circuit_interface_traits::CircuitFooterSpec;

impl<Chain> CircuitFooterSpec for ZkVoteCircuit<Chain> {
    fn summary_json_path() -> &'static str {
        "circuit_keys/zk_vote/zk_vote_summary.json"
    }
}

// ── Summary data for the ZK vote circuit ──────────────────────────────────────

/// Build-generated summary of the ZK voting circuit.
///
/// Matches the structure expected by [`CircuitSummaryLoader::load_summary`]
/// and [`CircuitSummaryLoader::generate_footer`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkVoteCircuitSummary {
    pub circuit_name: String,
    pub k: u32,
    pub instance_count: u8,
    pub num_fixed_columns: u8,
    pub num_advice_columns: u8,
    pub num_instance_columns: u8,
    pub degree: u8,
    pub has_lookups: bool,
    pub params_len: u32,
    pub vk_len: u32,
    pub cs_len: u32,
    pub num_selectors: u32,
    pub num_gates: u32,
}

impl Default for ZkVoteCircuitSummary {
    fn default() -> Self {
        Self {
            circuit_name: "zk_vote".to_string(),
            k: 12,
            instance_count: 4,
            num_fixed_columns: 2,
            num_advice_columns: 2,
            num_instance_columns: 1,
            degree: 12,
            has_lookups: false,
            params_len: 0,
            vk_len: 0,
            cs_len: 0,
            num_selectors: 2,
            num_gates: 10,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_name_is_correct() {
        assert_eq!(
            <ZkVoteCircuit<NeedsChain> as CircuitUploadable>::circuit_name(),
            "zk_vote"
        );
    }

    #[test]
    fn summary_json_path_ends_correctly() {
        let path = <ZkVoteCircuit<NeedsChain> as CircuitFooterSpec>::summary_json_path();
        assert!(path.ends_with("zk_vote_summary.json"));
        assert!(path.starts_with("circuit_keys"));
    }

    #[test]
    fn default_summary_has_expected_fields() {
        let s = ZkVoteCircuitSummary::default();
        assert_eq!(s.circuit_name, "zk_vote");
        assert_eq!(s.k, 12);
        assert_eq!(s.instance_count, 4);
        assert_eq!(s.degree, 12);
        assert!(!s.has_lookups);
    }

    #[test]
    fn summary_round_trips_through_json() {
        let s = ZkVoteCircuitSummary::default();
        let json = serde_json::to_string_pretty(&s).unwrap();
        let deserialized: ZkVoteCircuitSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, deserialized);
    }

    #[test]
    fn circuit_path_is_expected_glob() {
        let path =
            <ZkVoteCircuit<NeedsChain> as CircuitUploadable>::circuit_path(&Default::default());
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("circuit_keys"));
        assert!(path_str.contains("zk_vote"));
        assert!(path_str.ends_with("zk_vote_plonkish.bin"));
    }
}