//! Traits for circuit interfaces — mirrors `interface_traits` for ZK circuits.
//!
//! | Contract trait          | Circuit analogue           | Difference              |
//! |-------------------------|----------------------------|-------------------------|
//! | `ContractInstance<C>`   | `CircuitInstance<C>`       | No address, code_id only|
//! | `CwOrchUpload<C>`       | `CwOrchCircuitUpload<C>`   | Delegates to `Circuit`  |

use crate::{
    contract::circuits::circuit_paths::CircuitPathValidation,
    environment::{AccessConfig, ChainInfoOwned, ChainState, TxHandler, TxResponse, ZkTxHandler},
    error::CwEnvError,
};
use std::path::{Path, PathBuf};
use zk_cosmwasm::{cosmwasm_circuit::footer_flags, CircuitType};

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

use serde::{Deserialize, Serialize};
use zk_cosmwasm::CircuitFooter;

/// Trait for validating circuit binary paths and detecting missing footer metadata.
///
/// This trait implements the validation workflow:
/// 1. Check if `vk_combined.bin` exists with valid footer → ready to deploy
/// 2. Check if separate `verifying_key.bin` / `proving_key.bin` exist → needs footer append
/// 3. No keys found → needs key generation
pub trait CircuitPathValidator: CircuitUploadable {
    /// Validate the circuit path and return detailed status
    fn validate_circuit_path(chain: &ChainInfoOwned) -> CircuitPathValidation {
        let combined_path = Self::vk_combined_path(chain);
        let circuit_name = Self::circuit_name();

        // Step 1: Check if combined binary exists with valid footer
        if combined_path.exists() {
            return match std::fs::read(&combined_path) {
                Ok(data) => {
                    if data.len() < 32 {
                        return CircuitPathValidation::InvalidFooter {
                            path: combined_path,
                            reason: format!(
                                "File too small ({} bytes) to contain 32-byte footer",
                                data.len()
                            ),
                        };
                    }

                    // Read last 32 bytes as footer
                    let footer_bytes = &data[data.len() - 32..];
                    match CircuitFooter::from_bytes(footer_bytes) {
                        Ok(footer) => {
                            // Validate that declared sizes are consistent with file size
                            let declared_content_len = footer.params_len as usize
                                + footer.vk_len as usize
                                + footer.cs_len as usize;
                            let expected_file_len = declared_content_len + 32; // content + footer

                            if data.len() != expected_file_len {
                                return CircuitPathValidation::InvalidFooter {
                                    path: combined_path,
                                    reason: format!(
                                        "File size mismatch: got {} bytes, footer declares {} bytes (content: {} + footer: 32)",
                                        data.len(),
                                        expected_file_len,
                                        declared_content_len
                                    ),
                                };
                            }

                            if !footer.has_cs() {
                                return CircuitPathValidation::InvalidFooter {
                                    path: combined_path,
                                    reason: "Footer indicates no constraint system included (HAS_CS flag not set)".to_string(),
                                };
                            }

                            CircuitPathValidation::ValidCombined {
                                path: combined_path,
                                params_len: footer.params_len,
                                vk_len: footer.vk_len,
                                cs_len: footer.cs_len,
                                has_cs: footer.has_cs(),
                                has_lookups: footer.has_lookups(),
                            }
                        }
                        Err(e) => CircuitPathValidation::InvalidFooter {
                            path: combined_path,
                            reason: format!("Failed to parse footer: {:?}", e),
                        },
                    }
                }
                Err(e) => CircuitPathValidation::InvalidFooter {
                    path: combined_path,
                    reason: format!("Failed to read file: {}", e),
                },
            };
        }

        // Step 2: Check if separate keys exist (need footer append)
        let keys_dir = Self::vk_combined_path(chain)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(format!("{}_keys", circuit_name));

        let vk_path = keys_dir.join("verifying_key.bin");
        let pk_path = keys_dir.join("proving_key.bin");

        if vk_path.exists() || pk_path.exists() {
            let existing = if vk_path.exists() && pk_path.exists() {
                "both verifying_key.bin and proving_key.bin"
            } else if vk_path.exists() {
                "verifying_key.bin (proving_key.bin missing)"
            } else {
                "proving_key.bin (verifying_key.bin missing)"
            };

            log::warn!(
                "Circuit '{}' has separate keys ({}) but no combined vk_combined.bin with footer metadata. \
                 Run the key generation script to produce the combined binary.",
                circuit_name,
                existing,
            );

            return CircuitPathValidation::KeysExistButNotCombined { vk_path, pk_path };
        }

        // Step 3: No keys found at all
        let circuit_path = Self::circuit_path(chain);
        let mut searched = vec![combined_path.clone(), keys_dir.clone()];
        if circuit_path.exists() {
            searched.push(circuit_path);
        }

        log::error!(
            "No circuit keys found for '{}'. Searched:\n  - {}\n  - {}\n\
             Generate keys with: cargo run --bin gen_{}_keys",
            circuit_name,
            combined_path.display(),
            keys_dir.display(),
            circuit_name,
        );

        CircuitPathValidation::NoKeysFound {
            searched_dirs: searched,
        }
    }

    /// Returns true if the circuit is ready to deploy (valid combined binary exists)
    fn is_circuit_ready(chain: &ChainInfoOwned) -> bool {
        matches!(
            Self::validate_circuit_path(chain),
            CircuitPathValidation::ValidCombined { .. }
        )
    }
}

/// Circuit summary data extracted from the build process.
/// Serialized to JSON during key generation and loaded at deploy time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitSummary {
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

/// Trait for circuits that provide their footer metadata via a JSON summary.
/// Each circuit must specify where its build-generated summary file is located.
pub trait CircuitFooterSpec {
    /// Relative path to the circuit summary JSON file (from CARGO_MANIFEST_DIR).
    /// E.g., "artifacts/headstash_circuit_summary.json"
    fn summary_json_path() -> &'static str;
}

/// Trait for loading and validating circuit summaries.
/// Auto-implemented for all types that provide `CircuitFooterSpec`.
pub trait CircuitSummaryLoader: CircuitFooterSpec {
    /// Load the circuit summary from the JSON file.
    fn load_summary() -> Result<CircuitSummary, String> {
        let base = PathBuf::from(Self::summary_json_path());
        let path = if base.is_absolute() {
            base
        } else {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push(base);
            path
        };

        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read circuit summary at {:?}: {}", path, e))?;

        serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse circuit summary JSON: {}", e))
    }

    /// Generate a v2 CircuitFooter from the loaded summary.
    fn generate_footer(summary: &CircuitSummary) -> CircuitFooter {
        // let mut flags = footer_flags::HAS_CS;
        // if summary.has_lookups {
        //     flags |= footer_flags::HAS_LOOKUPS;
        // }

        CircuitFooter::new(
            CircuitType::Plonkish,
            summary.instance_count,
            summary.num_fixed_columns,
            summary.num_advice_columns,
            summary.num_instance_columns,
            summary.degree,
            summary.params_len,
            summary.vk_len,
            summary.cs_len,
            summary.num_selectors,
            summary.num_gates,
            summary.has_lookups,
            0, // crc32 placeholder
        )
    }

    /// Append footer to a binary file, creating the combined vk_combined.bin.
    fn append_footer_to_binary(
        binary_path: &Path,
        summary: &CircuitSummary,
    ) -> Result<PathBuf, String> {
        let footer = Self::generate_footer(summary);
        let footer_bytes = footer.to_bytes();

        let mut data = std::fs::read(binary_path)
            .map_err(|e| format!("Failed to read binary at {:?}: {}", binary_path, e))?;

        data.extend_from_slice(&footer_bytes);

        let output_path = binary_path.with_extension("vk_combined.bin");
        std::fs::write(&output_path, &data)
            .map_err(|e| format!("Failed to write combined binary: {}", e))?;

        Ok(output_path)
    }

    /// Validate that a combined binary's footer matches the expected summary.
    fn validate_combined_binary(
        combined_path: &Path,
        summary: &CircuitSummary,
    ) -> Result<(), String> {
        let data = std::fs::read(combined_path)
            .map_err(|e| format!("Failed to read combined binary: {}", e))?;

        if data.len() < 32 {
            return Err(format!(
                "Binary too small ({} bytes) to contain 32-byte footer",
                data.len()
            ));
        }

        let footer_bytes = &data[data.len() - 32..];
        let actual_footer = CircuitFooter::from_bytes(footer_bytes)
            .map_err(|e| format!("Failed to parse footer: {:?}", e))?;

        let expected_footer = Self::generate_footer(summary);

        // Validate content sizes match
        if actual_footer.params_len != expected_footer.params_len {
            return Err(format!(
                "params_len mismatch: footer says {}, summary says {}",
                actual_footer.params_len, expected_footer.params_len
            ));
        }
        if actual_footer.vk_len != expected_footer.vk_len {
            return Err(format!(
                "vk_len mismatch: footer says {}, summary says {}",
                actual_footer.vk_len, expected_footer.vk_len
            ));
        }
        if actual_footer.cs_len != expected_footer.cs_len {
            return Err(format!(
                "cs_len mismatch: footer says {}, summary says {}",
                actual_footer.cs_len, expected_footer.cs_len
            ));
        }

        // Validate total file size
        let expected_size = actual_footer.params_len as usize
            + actual_footer.vk_len as usize
            + actual_footer.cs_len as usize
            + 32;
        if data.len() != expected_size {
            return Err(format!(
                "File size mismatch: got {} bytes, expected {} (content: {} + footer: 32)",
                data.len(),
                expected_size,
                expected_size - 32
            ));
        }

        Ok(())
    }
}

// Blanket impl: anything providing CircuitFooterSpec gets CircuitSummaryLoader for free
impl<T: CircuitFooterSpec> CircuitSummaryLoader for T {}
