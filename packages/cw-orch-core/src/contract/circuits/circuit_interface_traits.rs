//! Traits for circuit interfaces — mirrors `interface_traits` for ZK circuits.
//!
//! | Contract trait          | Circuit analogue           | Difference              |
//! |-------------------------|----------------------------|-------------------------|
//! | `ContractInstance<C>`   | `CircuitInstance<C>`       | No address, code_id only|
//! | `CwOrchUpload<C>`       | `CwOrchCircuitUpload<C>`   | Delegates to `Circuit`  |

use crate::{
    contract::interface_traits::Uploadable,
    environment::{AccessConfig, ChainState, TxHandler, TxResponse},
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
    fn code_id(&self) -> Result<u64, CwEnvError> {
        Circuit::code_id(self.as_circuit())
    }

    /// Persist a `code_id` in the state store.
    fn set_code_id(&self, code_id: u64) {
        Circuit::set_code_id(self.as_circuit(), code_id)
    }

    /// Remove the `code_id` from the state store.
    fn remove_code_id(&self) {
        Circuit::remove_code_id(self.as_circuit())
    }

    /// Set a fallback `code_id` used when the state store has no entry.
    fn set_default_code_id(&mut self, code_id: u64) {
        Circuit::set_default_code_id(self.as_circuit_mut(), code_id)
    }
}

// ── CwOrchCircuitUpload ───────────────────────────────────────────────────────

/// Upload trait for circuit WASM artefacts.
///
/// Mirrors [`crate::contract::interface_traits::CwOrchUpload`].
/// Requires [`CircuitInstance`] for `code_id` state tracking and
/// [`Uploadable`] for the WASM bytes / path.
pub trait CwOrchCircuitUpload<Chain: TxHandler>:
    CircuitInstance<Chain> + Uploadable + Sized
{
    /// Upload the circuit WASM to the chain.
    fn upload(&self) -> Result<TxResponse<Chain>, CwEnvError> {
        self.as_circuit().upload(self)
    }

    /// Upload the circuit WASM with a custom instantiate access config.
    fn upload_with_access_config(
        &self,
        access_config: Option<AccessConfig>,
    ) -> Result<TxResponse<Chain>, CwEnvError> {
        self.as_circuit().upload_with_access_config(self, access_config)
    }
}

impl<T: CircuitInstance<Chain> + Uploadable, Chain: TxHandler> CwOrchCircuitUpload<Chain> for T {}
