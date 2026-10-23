//! Defaults for a script that boots a local Terp image.
//!
//! The chain id is the cw-orch localnet id, not `120u-1` or `morocco-1`.
//! The image tag defaults to the arm64 `v6.3.0` build. `TERP_IMAGE_VERSION`
//! or `ICT_IMAGE_VERSION` replaces that tag. The retired `local` tag is refused.

/// Clap env for the cold address that signs a session grant.
pub const CW_ORCH_GRANTER_ENV: &str = "CW_ORCH_GRANTER";

/// Chain id of a chain started by `--spawn`.
pub const SPAWN_CHAIN_ID: &str = "240u-1";

/// Coins sent from the genesis validator to one fresh account.
pub const SPAWN_FUND: &str = "100000000000uterp";

/// Image tag used when neither image env var is set.
pub const DEFAULT_TERP_IMAGE: &str = "v6.3.0";

/// Pick the Terp image tag a spawned chain should run.
pub fn resolve_image_version(raw: Option<&str>) -> Result<String, String> {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        Some("local") | Some("local-zk") => Err(
            "spawn refused: TERP_IMAGE_VERSION local is retired. Use a real tag such as v6.3.0."
                .into(),
        ),
        Some(version) => Ok(version.to_string()),
        None => Ok(DEFAULT_TERP_IMAGE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_image_uses_v6_3_0_and_local_is_refused() {
        assert_eq!(resolve_image_version(None).unwrap(), "v6.3.0");
        assert_eq!(resolve_image_version(Some("  ")).unwrap(), "v6.3.0");
        assert_eq!(resolve_image_version(Some("v6.3.0-dev")).unwrap(), "v6.3.0-dev");
        assert!(resolve_image_version(Some("local")).unwrap_err().contains("retired"));
        assert!(resolve_image_version(Some("local-zk")).is_err());
        assert_eq!(SPAWN_CHAIN_ID, "240u-1");
        assert!(SPAWN_FUND.ends_with("uterp"));
        assert_eq!(CW_ORCH_GRANTER_ENV, "CW_ORCH_GRANTER");
    }
}
