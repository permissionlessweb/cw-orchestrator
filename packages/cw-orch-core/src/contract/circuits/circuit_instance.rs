//! Circuit instance — mirrors `contract_instance::Contract<Chain>` for ZK
//! circuit artefacts uploaded as CosmWasm WASM code.
//!
//! Circuits have a `code_id` (assigned on upload) but no runtime `address`.
//! On Terp Network the on-chain verifying logic is invoked through the
//! `zk-wasmvm` host extension, not through a contract address.

use crate::{
    environment::{AccessConfig, ChainState, IndexResponse, StateInterface, TxHandler, TxResponse},
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
    pub default_code_id: Option<u64>,
}

// ── Constructors & helpers ────────────────────────────────────────────────────

impl<Chain> Circuit<Chain> {
    /// Create a new circuit instance.
    pub fn new(id: impl ToString, chain: Chain) -> Self {
        Circuit {
            id: id.to_string(),
            chain,
            default_code_id: None,
        }
    }

    /// Return a reference to the underlying chain / environment.
    pub fn environment(&self) -> &Chain {
        &self.chain
    }

    /// Set a fallback `code_id` used when the state store has no entry.
    pub fn set_default_code_id(&mut self, code_id: u64) {
        self.default_code_id = Some(code_id);
    }
}

// ── State operations ──────────────────────────────────────────────────────────

impl<Chain: ChainState> Circuit<Chain> {
    /// Read the `code_id` from the state store, falling back to
    /// [`Self::default_code_id`] if none is found.
    pub fn code_id(&self) -> Result<u64, CwEnvError> {
        self.chain
            .state()
            .get_code_id(&self.id)
            .or(self
                .default_code_id
                .ok_or(CwEnvError::CodeIdNotInStore(self.id.clone())))
    }

    /// Persist a `code_id` in the state store.
    pub fn set_code_id(&self, code_id: u64) {
        self.chain.state().set_code_id(&self.id, code_id)
    }

    /// Remove the `code_id` entry from the state store.
    pub fn remove_code_id(&self) {
        self.chain.state().remove_code_id(&self.id)
    }
}

// ── Chain operations ──────────────────────────────────────────────────────────

impl<Chain: TxHandler> Circuit<Chain> {
    /// Upload the circuit WASM artefact with a custom access config.
    pub fn upload_with_access_config(
        &self,
        source: &impl Uploadable,
        access_config: Option<AccessConfig>,
    ) -> Result<TxResponse<Chain>, CwEnvError> {
        log::info!(
            target: &contract_target(),
            "[circuit][{}][Upload]",
            self.id,
        );

        let resp = self
            .chain
            .upload_with_access_config(source, access_config)
            .map_err(Into::into)?;
        let code_id = resp.uploaded_code_id()?;
        self.set_code_id(code_id);
        log::info!(
            target: &contract_target(),
            "[circuit][{}][Uploaded] code_id {}",
            self.id,
            code_id
        );
        log::debug!(
            target: &contract_target(),
            "[circuit][{}][Uploaded] response {:?}",
            self.id,
            resp
        );
        Ok(resp)
    }

    /// Upload the circuit WASM artefact with the default access config.
    pub fn upload(&self, source: &impl Uploadable) -> Result<TxResponse<Chain>, CwEnvError> {
        self.upload_with_access_config(source, None)
    }
}
