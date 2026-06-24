//! ZK circuit integration for cw-orch — feature `terp`.
//!
//! Provides a [`Circuit<Chain>`] struct and associated traits that mirror the
//! contract upload infrastructure ([`crate::contract::Contract`],
//! [`crate::contract::interface_traits::ContractInstance`]) but specialised
//! for ZK circuit artefacts:
//!
//! - [`Circuit<Chain>`] — tracks a circuit's `code_id` in the cw-orch state
//!   store after an on-chain upload.  No address field (circuits are invoked
//!   through the `zk-wasmvm` host extension, not as contract addresses).
//!
//! - [`CircuitInstance<Chain>`] — trait analogue of `ContractInstance`.
//!
//! - [`CwOrchCircuitUpload<Chain>`] — blanket upload trait analogous to
//!   `CwOrchUpload`.
//!
//! - [`CircuitPath`] / [`CircuitsDir`] / [`CircuitSpec`] — path helpers
//!   analogous to `WasmPath` / `ArtifactsDir`, with spec-aware preflight
//!   validation of circuit binary files (VK, PK, params).
//!
//! # Feature gate
//! This entire module requires `--features terp` on `cw-orch-core`.
mod circuit_instance;
pub mod circuit_interface_traits;
mod circuit_paths;
pub use circuit_instance::Circuit;
pub use circuit_interface_traits::{CircuitInstance, CwOrchCircuitUpload};
pub use circuit_paths::{CircuitPath, CircuitSpec, CircuitsDir};

