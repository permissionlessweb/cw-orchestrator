//! Ephemeral broadcaster for a cw-orch-kms session.
//!
//! The cold key is the granter. This key signs the grant transaction and the
//! later contract messages. When the chain's mnemonic variable is empty, a
//! fresh 24-word key is placed in that variable for this process only.
//!
//! Secrets are never persisted: the phrase is not written to disk, not
//! printed, and not read back from any file. A key that must outlive the
//! process (for example a contract owner) must not be the ephemeral key; pass
//! a DAO or a cold address as owner/admin instead, or export the variable
//! from your own secret store before the run.

use cw_orch_core::environment::ChainKind;
use cw_orch_daemon::env::{
    LOCAL_MNEMONIC_ENV_NAME, MAIN_MNEMONIC_ENV_NAME, TEST_MNEMONIC_ENV_NAME,
};
use std::sync::Mutex;

static EPHEMERAL_LOCK: Mutex<()> = Mutex::new(());

/// Fill the mnemonic variable for `kind` when it is unset or blank.
///
/// An existing value is left unchanged, so a later session build uses the
/// same key as the address preview. Nothing touches the filesystem.
pub fn ensure_ephemeral_mnemonic(kind: ChainKind) -> Result<(), String> {
    let name = mnemonic_env(kind)?;
    let _guard = EPHEMERAL_LOCK
        .lock()
        .map_err(|_| "ephemeral signer lock poisoned".to_string())?;
    if let Ok(existing) = std::env::var(name) {
        if !existing.trim().is_empty() {
            return Ok(());
        }
    }
    let mnemonic = bip39::Mnemonic::generate(24)
        .map_err(|err| format!("ephemeral signer refused: {err}"))?;
    std::env::set_var(name, mnemonic.to_string());
    println!("generated ephemeral signer (process memory only, not persisted)");
    Ok(())
}

fn mnemonic_env(kind: ChainKind) -> Result<&'static str, String> {
    match kind {
        ChainKind::Mainnet => Ok(MAIN_MNEMONIC_ENV_NAME),
        ChainKind::Testnet => Ok(TEST_MNEMONIC_ENV_NAME),
        ChainKind::Local => Ok(LOCAL_MNEMONIC_ENV_NAME),
        ChainKind::Unspecified => Err("ephemeral signer refused: chain kind is unset".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_is_generated_once_in_memory_and_never_written() {
        let home = std::env::temp_dir().join("cw-orch-ephemeral-nopersist");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let old_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &home);
        let previous = std::env::var(TEST_MNEMONIC_ENV_NAME).ok();
        std::env::remove_var(TEST_MNEMONIC_ENV_NAME);
        ensure_ephemeral_mnemonic(ChainKind::Testnet).unwrap();
        let first = std::env::var(TEST_MNEMONIC_ENV_NAME).unwrap();
        assert_eq!(first.split_whitespace().count(), 24);
        ensure_ephemeral_mnemonic(ChainKind::Testnet).unwrap();
        assert_eq!(std::env::var(TEST_MNEMONIC_ENV_NAME).unwrap(), first);
        assert!(!home.join(".cw-orch").exists(), "no secret directory may be created");
        assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0, "nothing written");
        match previous {
            Some(value) => std::env::set_var(TEST_MNEMONIC_ENV_NAME, value),
            None => std::env::remove_var(TEST_MNEMONIC_ENV_NAME),
        }
        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        }
    }

    #[test]
    fn unspecified_chain_kind_is_refused() {
        assert!(ensure_ephemeral_mnemonic(ChainKind::Unspecified).is_err());
    }
}
