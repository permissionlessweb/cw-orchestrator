//! Circuit artifact paths — mirrors `contract::paths` for ZK circuit binary
//! files (verifying keys, proving keys, SRS params).
//!
//! Unlike [`WasmPath`](crate::contract::WasmPath) which only validates the
//! `.wasm` extension, [`CircuitPath`] additionally runs a **spec-aware
//! preflight check** on the file header/footer bytes before any chain
//! interaction.
//!
//! # Spec extensibility
//! [`CircuitSpec`] is `#[non_exhaustive]`.  New variants will be added as the
//! `zk-wasmvm` host supports additional proof systems.  For now only
//! [`CircuitSpec::Halo2Plonk`] exists.

use crate::error::CwEnvError;
use cosmwasm_std::Checksum;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub use crate::contract::ArtifactsDir;

// ─── CircuitSpec ──────────────────────────────────────────────────────────────

/// Proof-system format of a circuit artifact file.
///
/// Each variant defines the validation rules applied during the
/// [`CircuitPath`] preflight check.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitSpec {
    /// Halo2 PLONK proving key or verifying key.
    ///
    /// Validates minimum file size.  Magic header/footer bytes will be added
    /// once the `zk-wasmvm` on-chain binary format is finalised.
    Halo2Plonk,
}

impl CircuitSpec {
    /// Minimum byte length considered valid for this spec.
    const fn min_bytes(self) -> usize {
        match self {
            CircuitSpec::Halo2Plonk => 32,
        }
    }

    /// Validate raw bytes against this spec's header/footer rules.
    pub fn validate_bytes(self, bytes: &[u8]) -> Result<(), CwEnvError> {
        if bytes.len() < self.min_bytes() {
            return Err(CwEnvError::StdErr(format!(
                "circuit spec {:?}: file too small ({} bytes, minimum {})",
                self,
                bytes.len(),
                self.min_bytes(),
            )));
        }
        match self {
            CircuitSpec::Halo2Plonk => {
                // TODO: validate zk-wasmvm Halo2 PLONK magic header/footer
                // once the on-chain binary format is finalised.
                Ok(())
            }
        }
    }

    /// Conventional file extension for artifacts conforming to this spec.
    pub const fn extension(self) -> &'static str {
        match self {
            CircuitSpec::Halo2Plonk => "bin",
        }
    }
}

// ─── CircuitPath ──────────────────────────────────────────────────────────────

/// Validated path to a circuit artifact file (proving key, verifying key,
/// SRS params).
///
/// Mirrors [`crate::contract::WasmPath`] but performs a spec-aware preflight
/// check on the file bytes at construction time.
///
/// # Example
/// ```no_run
/// use cw_orch_core::contract::circuits::{CircuitPath, CircuitSpec};
///
/// let path = CircuitPath::new("keys/verifying_key.bin", CircuitSpec::Halo2Plonk).unwrap();
/// let checksum = path.checksum().unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct CircuitPath {
    inner: PathBuf,
    spec: CircuitSpec,
}

impl CircuitPath {
    /// Create a new `CircuitPath`, validating that the file exists and its
    /// bytes conform to `spec`.
    pub fn new(path: impl Into<PathBuf>, spec: CircuitSpec) -> Result<Self, CwEnvError> {
        let p: PathBuf = path.into();
        assert!(p.exists(), "circuit path {} does not exist", p.display());
        let mut file = std::fs::File::open(&p)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        spec.validate_bytes(&bytes)?;
        Ok(Self { inner: p, spec })
    }

    /// The underlying path to the artifact file.
    pub fn path(&self) -> &Path {
        self.inner.as_path()
    }

    /// The spec this path was validated against.
    pub fn spec(&self) -> CircuitSpec {
        self.spec
    }

    /// SHA-256 checksum of the artifact bytes.
    pub fn checksum(&self) -> Result<Checksum, CwEnvError> {
        let mut file = std::fs::File::open(self.path())?;
        let mut bytes = Vec::<u8>::new();
        file.read_to_end(&mut bytes)?;
        Ok(Checksum::generate(&bytes))
    }
}

// ─── CircuitsDir ─────────────────────────────────────────────────────────────
pub struct CircuitsDir(PathBuf);

impl CircuitsDir {
    /// Create from an explicit path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        assert!(
            path.exists(),
            "circuits dir {} does not exist",
            path.display()
        );
        Self(path)
    }
    /// Simple auto-detection: always points to workspace `artifacts/`
    pub fn auto(start_path: Option<String>) -> Self {
        let base = start_path.unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").to_string());
        let mut current = PathBuf::from(&base);

        // Walk up to workspace root and append `artifacts`
        loop {
            let candidate = current.join("artifacts");
            if candidate.exists() {
                return Self::new(candidate);
            }
            if !current.pop() {
                panic!("Could not find `artifacts` directory from {}", base);
            }
        }
    }

    /// Path to this directory.
    pub fn path(&self) -> &PathBuf {
        &self.0
    }

    /// Find `{circuit_name}_{kind}.bin` in artifacts/
    pub fn find_circuit_path(
        &self,
        circuit_name: &str,
        artifact_name: &str, // "vk" or "pk"
        spec: CircuitSpec,
    ) -> Result<CircuitPath, CwEnvError> {
        let filename = format!("{}_{}.{}", circuit_name, artifact_name, spec.extension());
        let path = self.0.join(filename);
        CircuitPath::new(path, spec).map_err(|e| {
            CwEnvError::StdErr(format!(
                "circuit artifact '{artifact_name}' for '{circuit_name}': {e}"
            ))
        })
    }

    pub fn verifying_key(
        &self,
        circuit_name: &str,
        spec: CircuitSpec,
    ) -> Result<CircuitPath, CwEnvError> {
        self.find_circuit_path(circuit_name, "vk", spec)
    }

    pub fn proving_key(
        &self,
        circuit_name: &str,
        spec: CircuitSpec,
    ) -> Result<CircuitPath, CwEnvError> {
        self.find_circuit_path(circuit_name, "pk", spec)
    }

    /// Convenience: find the SRS params for a named circuit.
    pub fn params(&self, circuit_name: &str, spec: CircuitSpec) -> Result<CircuitPath, CwEnvError> {
        self.find_circuit_path(circuit_name, "params", spec)
    }
}

/// Result of circuit path validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitPathValidation {
    /// Combined binary exists with valid footer (`zk_cosmwasm::CircuitFooter`).
    ValidCombined {
        path: PathBuf,
        /// Matches footer field `param_len` (not the older `params_len` spelling).
        param_len: u32,
        vk_len: u32,
        cs_len: u32,
        /// Derived as `cs_len > 0` (footer no longer carries HAS_CS flags).
        has_cs: bool,
    },
    /// Separate keys exist but haven't been combined with footer yet
    KeysExistButNotCombined { vk_path: PathBuf, pk_path: PathBuf },
    /// No keys found at all
    NoKeysFound { searched_dirs: Vec<PathBuf> },
    /// Combined binary exists but footer is invalid or missing
    InvalidFooter { path: PathBuf, reason: String },
}

#[macro_export]
/// Creates a [`CircuitsDir`] by searching upward from the **call-site crate**
/// for a `circuit_keys` directory.
///
/// Analogous to [`crate::contract::artifacts_dir_from_workspace`].
macro_rules! circuits_dir_from_workspace {
    () => {
        $crate::contract::circuits::CircuitsDir::auto(Some(env!("CARGO_MANIFEST_DIR").to_string()))
    };
}
