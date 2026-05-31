//! Circuit instance — mirrors `contract_instance::Contract<Chain>` for ZK
//! circuit artefacts uploaded as CosmWasm WASM code.
//!
//! Circuits have a `code_id` (assigned on upload) but no runtime `address`.
//! On Terp Network the on-chain verifying logic is invoked through the
//! `zk-wasmvm` host extension, not through a contract address.

use crate::{
    contract::circuits::circuit_interface_traits::CircuitUploadable,
    environment::{
        AccessConfig, ChainState, IndexResponse, StateInterface, TxHandler, TxResponse, ZkTxHandler,
    },
    error::CwEnvError,
    log::contract_target,
};

use super::super::interface_traits::Uploadable;

/// An uploaded circuit artefact tracked in the cw-orch state store.
///
/// Mirrors [`crate::contract::Contract`] but only carries a `code_id` — no
/// address — because circuits are invoked through the `zk-wasmvm` host
/// extension rather than a CosmWasm contract address.
#[derive(Clone)]
pub struct Circuit<Chain> {
    /// Unique identifier used as the key in the state store.
    pub id: String,
    /// Chain / environment handle.
    pub(crate) chain: Chain,
    /// Fallback `code_id` when none is present in the state store.
    pub default_zk_id: Option<u64>,
}

// ── Constructors & helpers ────────────────────────────────────────────────────

impl<Chain> Circuit<Chain> {
    /// Create a new circuit instance.
    pub fn new(id: impl ToString, chain: Chain) -> Self {
        Circuit {
            id: id.to_string(),
            chain,
            default_zk_id: None,
        }
    }

    /// Return a reference to the underlying chain / environment.
    pub fn environment(&self) -> &Chain {
        &self.chain
    }

    /// Set a fallback `zk_id` used when the state store has no entry.
    pub fn set_default_zk_id(&mut self, zk_id: u64) {
        self.default_zk_id = Some(zk_id);
    }
}

// ── State operations ──────────────────────────────────────────────────────────

impl<Chain: ChainState> Circuit<Chain> {
    /// Read the `zk_id` from the state store, falling back to
    /// [`Self::default_zk_id`] if none is found.
    pub fn zk_id(&self) -> Result<u64, CwEnvError> {
        let state_zk_id = self.chain.state().get_code_id(&self.id);
        // If the code_ids is not present, we default to the default code_id or an error
        state_zk_id.or(self
            .default_zk_id
            .ok_or(CwEnvError::CodeIdNotInStore(self.id.clone())))
    }

    /// Persist a `code_id` in the state store.
    pub fn set_zk_id(&self, zk_id: u64) {
        self.chain.state().set_code_id(&self.id, zk_id)
    }

    /// Remove the `zk_id` entry from the state store.
    pub fn remove_zk_id(&self) {
        self.chain.state().remove_code_id(&self.id)
    }
}

// ── Chain operations ──────────────────────────────────────────────────────────
impl<Chain: ZkTxHandler> Circuit<Chain> {
    /// Upload a raw zk-circuit binary (no wasm wrapper).
    /// Uses `store-circuit` under the hood.
    pub fn upload_circuit(
        &self,
        source: &impl CircuitUploadable,
    ) -> Result<TxResponse<Chain>, CwEnvError> {
        log::info!(
            target: &contract_target(),
            "[circuit][{}][upload_circuit]",
            self.id,
        );

        let resp = self.chain.upload_circuit(source)?;
        let zk_id = resp.uploaded_zk_id()?;
        self.set_zk_id(zk_id);

        log::info!(
            target: &contract_target(),
            "[circuit][{}][upload_circuit] zk_id {}",
            self.id,
            zk_id
        );
        log::debug!(
            target: &contract_target(),
            "[circuit][{}][upload_circuit] response {:?}",
            self.id,
            resp
        );
        Ok(resp)
    }

    /// Upload a raw zk-circuit with custom access config.
    pub fn upload_circuit_with_access_config(
        &self,
        source: &impl CircuitUploadable,
        access_config: Option<AccessConfig>,
    ) -> Result<TxResponse<Chain>, CwEnvError>
    where
        CwEnvError: From<<Chain as TxHandler>::Error>,
    {
        log::info!(
            target: &contract_target(),
            "[circuit][{}][upload_circuit_with_access_config]",
            self.id,
        );

        let resp = self
            .chain
            .upload_circuit_with_access_config(source, access_config)?;
        let zk_id = resp.uploaded_zk_id()?;
        self.set_zk_id(zk_id);

        log::info!(
            target: &contract_target(),
            "[circuit][{}][upload_circuit_with_access_config] zk_id {}",
            self.id,
            zk_id
        );
        Ok(resp)
    }

    /// Upload a WASM artifact with its Halo2 verifying key.
    /// Uses `store-with-vk` under the hood.
    pub fn upload_with_vk(
        &self,
        _source: &impl Uploadable,
        _vk_bytes: &[u8],
    ) -> Result<Chain::Response, Chain::Error> {
        unimplemented!("not yet implemented: uploading with vk")
    }

    /// Upload wasm+vk with custom access config.
    pub fn upload_with_vk_and_access_config(
        &self,
        _source: &impl Uploadable,
        _vk_bytes: &[u8],
        _access_config: Option<AccessConfig>,
    ) -> Result<Chain::Response, Chain::Error> {
        unimplemented!("not yet implemented: uploading with vk")
    }
}
