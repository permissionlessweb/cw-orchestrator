//! Traits for circuit interfaces — mirrors `interface_traits` for ZK circuits.
//!
//! | Contract trait          | Circuit analogue           | Difference              |
//! |-------------------------|----------------------------|-------------------------|
//! | `ContractInstance<C>`   | `CircuitInstance<C>`       | No address, code_id only|
//! | `CwOrchUpload<C>`       | `CwOrchCircuitUpload<C>`   | Delegates to `Circuit`  |

use std::path::PathBuf;

use crate::{
    environment::{AccessConfig, ChainInfoOwned, ChainState, TxHandler, TxResponse, ZkTxHandler},
    error::CwEnvError,
};

use super::circuit_instance::Circuit;

// ── CircuitInstance ───────────────────────────────────────────────────────────

/// Interface to the underlying [`Circuit`] struct.
///
/// Mirrors [`crate::contract::interface_traits::ContractInstance`] but without
/// address tracking — circuits are identified by `code_id` only.
pub trait CircuitInstance<Chain: ChainState> {
    /// Return a reference to the underlying [`Circuit`].
    fn as_circuit(&self) -> &Circuit<Chain>;

    /// Return a mutable reference to the underlying [`Circuit`].
    fn as_circuit_mut(&mut self) -> &mut Circuit<Chain>;

    /// The circuit's unique state-store identifier.
    fn id(&self) -> String {
        self.as_circuit().id.clone()
    }

    /// Read the uploaded `code_id` from the state store.
    fn zk_id(&self) -> Result<u64, CwEnvError> {
        Circuit::zk_id(self.as_circuit())
    }

    /// Persist a `code_id` in the state store.
    fn set_zk_id(&self, code_id: u64) {
        Circuit::set_zk_id(self.as_circuit(), code_id)
    }

    /// Remove the `code_id` from the state store.
    fn remove_zk_id(&self) {
        Circuit::remove_zk_id(self.as_circuit())
    }

    /// Set a fallback `code_id` used when the state store has no entry.
    fn set_default_zk_id(&mut self, code_id: u64) {
        Circuit::set_default_zk_id(self.as_circuit_mut(), code_id)
    }
}

// ── CwOrchCircuitUpload ───────────────────────────────────────────────────────

/// Upload trait for circuit artefacts.
///
/// Mirrors [`crate::contract::interface_traits::CwOrchUpload`].
/// Requires [`CircuitInstance`] for `zk_id` state tracking and
/// [`CircuitUploadable`] for the WASM bytes / path.
pub trait CwOrchCircuitUpload<Chain: ZkTxHandler>:
    CircuitInstance<Chain> + CircuitUploadable + Sized
{
    /// Upload the circuit WASM to the chain.
    fn upload_circuit(&self) -> Result<TxResponse<Chain>, CwEnvError> {
        self.as_circuit().upload_circuit(self)
    }

    /// Upload the circuit WASM with a custom instantiate access config.
    fn upload_circuit_with_access_config(
        &self,
        access_config: Option<AccessConfig>,
    ) -> Result<TxResponse<Chain>, CwEnvError>
    where
        CwEnvError: From<<Chain as TxHandler>::Error>,
    {
        self.as_circuit()
            .upload_circuit_with_access_config(self, access_config)
    }
}

/// Trait for uploadable ZK circuit binaries.
/// Unlike `Uploadable`, this does NOT enforce a `.wasm` file extension.
pub trait CircuitUploadable {
    /// Returns the filename of the circuit binary (without path).
    fn circuit_name() -> String;

    /// Returns the path to the circuit binary file.
    /// Default: looks in artifacts/ directory using circuit_name()
    fn circuit_path(_chain: &ChainInfoOwned) -> PathBuf {
        let mut path = PathBuf::from("artifacts");
        path.push(Self::circuit_name());
        path
    }

    /// Reads the circuit binary bytes from disk.
    /// Panics if the file cannot be read.
    fn circuit_bytes(chain: &ChainInfoOwned) -> Vec<u8> {
        let path = Self::circuit_path(chain);

        // We unwrap the result here, which will panic if the file is not found or unreadable
        std::fs::read(&path).expect(&format!(
            "Failed to read circuit binary at path: {}",
            path.to_string_lossy()
        ))
    }
    /// Returns the path to the VK combined binary.
    /// Default: looks in circuit_keys/<circuit_name>/vk_combined.bin
    fn vk_combined_path(_chain: &ChainInfoOwned) -> PathBuf {
        let mut path = PathBuf::from("circuit_keys");
        path.push(Self::circuit_name());
        path.push("vk_combined.bin");
        path
    }

    /// Reads the VK combined binary bytes from disk.
    /// Panics if the file cannot be read.
    fn vk_combined_bytes(chain: &ChainInfoOwned) -> Vec<u8> {
        let path = Self::vk_combined_path(chain);
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!(
                "Failed to read VK combined binary at path {}: {}",
                path.to_string_lossy(),
                e
            )
        })
    }
}

/// Trait that indicates that the contract can be uploaded.
pub trait CwOrchUploadCircuit<Chain: ZkTxHandler>:
    CircuitInstance<Chain> + CircuitUploadable + Sized
{
    /// upload the contract to the configured environment.
    fn upload(&self) -> Result<Chain::Response, CwEnvError>
    where
        CwEnvError: From<<Chain as TxHandler>::Error>,
    {
        self.as_circuit().upload_circuit(self)
    }

    /// upload the contract to the configured environment and specify the permissions for instantiating
    fn upload_with_access_config(
        &self,
        access_config: Option<AccessConfig>,
    ) -> Result<Chain::Response, CwEnvError>
    where
        CwEnvError: From<<Chain as TxHandler>::Error>,
    {
        self.as_circuit()
            .upload_circuit_with_access_config(self, access_config)
    }
}
