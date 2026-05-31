// //! Integration test for ZkVoteCircuit upload lifecycle.
// //!
// //! Verifies that [`ZkVoteCircuit`] satisfies the [`CircuitUploadable`],
// //! [`CircuitFooterSpec`], and [`CircuitInstance`] trait bounds required by
// //! the cw-orchestrator circuit pipeline.  These are off-chain checks — the
// //! `CircuitUploadable` methods are all static (no running chain needed).
// //!
// //! Full end-to-end (upload to a live Daemon) requires a running zk-wasmd
// //! testnet and is exercised by a manual integration script rather than
// //! `cargo test`.

// use cw_orch_core::{
//     contract::circuits::circuit_interface_traits::{
//         CircuitFooterSpec, CircuitUploadable,
//     },
//     environment::ChainInfoOwned,
// };
// use zk_vote_circuit::types::{NeedsChain, ZkVoteCircuit};

// // ── Runtime path tests ────────────────────────────────────────────────────────

// /// `circuit_name` returns the string expected by the circuit pipeline.
// #[test]
// fn circuit_name_is_correct() {
//     assert_eq!(
//         <ZkVoteCircuit<NeedsChain> as CircuitUploadable>::circuit_name(),
//         "zk_vote",
//     );
// }

// /// `circuit_path` resolves without panic.
// #[test]
// fn circuit_path_resolves() {
//     let path = <ZkVoteCircuit<NeedsChain> as CircuitUploadable>::circuit_path(&dummy_chain_info());
//     let s = path.to_string_lossy();
//     assert!(
//         s.contains("circuit_keys"),
//         "expected circuit_keys in path, got: {s}",
//     );
//     assert!(
//         s.contains("zk_vote"),
//         "expected zk_vote in path, got: {s}",
//     );
// }

// /// `vk_combined_path` resolves without panic.
// #[test]
// fn vk_combined_path_resolves() {
//     let path =
//         <ZkVoteCircuit<NeedsChain> as CircuitUploadable>::vk_combined_path(&dummy_chain_info());
//     let s = path.to_string_lossy();
//     assert!(
//         s.contains("vk_combined"),
//         "expected vk_combined in path, got: {s}",
//     );
// }

// /// `summary_json_path` returns the expected relative path.
// #[test]
// fn summary_json_path_is_correct() {
//     assert_eq!(
//         <ZkVoteCircuit<NeedsChain> as CircuitFooterSpec>::summary_json_path(),
//         "circuit_keys/zk_vote/zk_vote_summary.json",
//     );
// }

// // ── Test helpers ──────────────────────────────────────────────────────────────

// /// Minimal chain-info for static-path resolution (only the ChainInfoOwned
// /// struct is needed by the static CircuitUploadable methods; fields are
// /// irrelevant for path computation).
// fn dummy_chain_info() -> ChainInfoOwned {
//     ChainInfoOwned::default()
// }