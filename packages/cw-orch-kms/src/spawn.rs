//! Boot the local Terp image for a script.
//!
//! This is a Docker chain, not a mock. The container stays up until
//! [`SpawnedTerp`] is dropped. The signer is `LOCAL_MNEMONIC` when that
//! variable is set. Otherwise a fresh 24-word key is generated for this
//! process and not printed.

use cw_orch_core::environment::ChainInfoOwned;
use cw_orch_daemon::env::LOCAL_MNEMONIC_ENV_NAME;
use ict_rs::chain::Chain;
use ict_rs::prelude::*;
use ict_rs::testing::env::TestEnv;
use ict_rs_cw_orch::chain_info_from_cosmos;

use crate::spawn_plan::{resolve_image_version, SPAWN_CHAIN_ID, SPAWN_FUND};

/// A running local Terp node and the signer it funded.
pub struct SpawnedTerp {
    chain: CosmosChain,
    info: ChainInfoOwned,
    signer: String,
    rt: tokio::runtime::Runtime,
    /// False when this process joined a chain another process already started.
    stop_on_drop: bool,
}

impl SpawnedTerp {
    /// Start one validator from the Terp image and fund the signer.
    pub fn boot() -> Result<Self, String> {
        let version = ensure_image_env()?;
        let rt = tokio::runtime::Runtime::new().map_err(|err| format!("spawn refused: {err}"))?;
        let (chain, info, signer) = rt.block_on(start_chain(version))?;
        Ok(Self {
            chain,
            info,
            signer,
            rt,
            stop_on_drop: true,
        })
    }

    /// Join chain `240u-1` when its SpawnedTerp validator is already running.
    ///
    /// Returns `Ok(None)` when that container is not running. A running chain
    /// is not stopped when this value is dropped.
    pub fn attach() -> Result<Option<Self>, String> {
        if !ict_rs::chain::zcinti::validator_container_running()? {
            return Ok(None);
        }
        let _version = ensure_image_env()?;
        let rt = tokio::runtime::Runtime::new().map_err(|err| format!("spawn refused: {err}"))?;
        let (chain, info, signer) = rt.block_on(attach_chain())?;
        Ok(Some(Self {
            chain,
            info,
            signer,
            rt,
            stop_on_drop: false,
        }))
    }

    /// gRPC endpoint and gas settings of the chain that just started.
    pub fn chain_info(&self) -> ChainInfoOwned {
        self.info.clone()
    }

    /// Bech32 address of the funded signer.
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// Send [`SPAWN_FUND`] from the genesis validator to `address`.
    pub fn fund(&self, address: &str) -> Result<(), String> {
        if address.is_empty() {
            return Err("spawn refused: empty fund address".into());
        }
        let chain = &self.chain;
        self.rt.block_on(fund_address(chain, address))
    }
}

impl Drop for SpawnedTerp {
    fn drop(&mut self) {
        if !self.stop_on_drop {
            return;
        }
        let rt = &self.rt;
        let chain = &mut self.chain;
        if let Err(err) = rt.block_on(chain.stop()) {
            println!("spawn stop refused: {err}");
        }
    }
}

fn signer_mnemonic() -> Result<String, String> {
    crate::ensure_ephemeral_mnemonic(cw_orch_core::environment::ChainKind::Local)?;
    std::env::var(LOCAL_MNEMONIC_ENV_NAME).map_err(|err| format!("spawn refused: {err}"))
}

fn ensure_image_env() -> Result<String, String> {
    let version = image_version_from_env()?;
    if std::env::var("TERP_IMAGE_VERSION")
        .ok()
        .filter(|value| !value.is_empty())
        .is_none()
        && std::env::var("ICT_IMAGE_VERSION")
            .ok()
            .filter(|value| !value.is_empty())
            .is_none()
    {
        std::env::set_var("TERP_IMAGE_VERSION", &version);
    }
    Ok(version)
}

fn image_version_from_env() -> Result<String, String> {
    let raw = std::env::var("TERP_IMAGE_VERSION")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("ICT_IMAGE_VERSION")
                .ok()
                .filter(|value| !value.is_empty())
        });
    resolve_image_version(raw.as_deref())
}

async fn start_chain(version: String) -> Result<(CosmosChain, ChainInfoOwned, String), String> {
    let runtime = IctRuntime::Docker(DockerConfig::default())
        .into_backend()
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    let mut cfg = TestEnv::terp_config();
    cfg.chain_id = SPAWN_CHAIN_ID.to_string();
    let mut chain = CosmosChain::new(cfg, 1, 0, runtime);
    chain
        .initialize(&TestContext {
            test_name: ict_rs::chain::zcinti::SPAWN_TEST_NAME.into(),
            network_id: String::new(),
        })
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    chain
        .start(&[])
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    let (info, signer) = prepare_signer(&chain).await?;
    let image = chain
        .config()
        .images
        .first()
        .map(|image| format!("{}:{}", image.repository, image.version))
        .unwrap_or(version);
    println!(
        "spawned {SPAWN_CHAIN_ID} grpc {} rpc {} lcd {} image {image}",
        info.grpc_urls.first().map(String::as_str).unwrap_or(""),
        info.rpc_urls.first().map(String::as_str).unwrap_or(""),
        info.lcd_url.as_deref().unwrap_or("")
    );
    println!("funded signer {signer}");
    Ok((chain, info, signer))
}

async fn attach_chain() -> Result<(CosmosChain, ChainInfoOwned, String), String> {
    let runtime = IctRuntime::Docker(DockerConfig::default())
        .into_backend()
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    let mut cfg = TestEnv::terp_config();
    cfg.chain_id = SPAWN_CHAIN_ID.to_string();
    let mut chain = CosmosChain::new(cfg, 1, 0, runtime);
    let adopted = chain
        .adopt_running_validator(
            ict_rs::chain::zcinti::SPAWN_TEST_NAME,
            &ict_rs::chain::zcinti::network_name(),
        )
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    if !adopted {
        return Err(format!(
            "spawn refused: {SPAWN_CHAIN_ID} is running but has no published grpc port"
        ));
    }
    let (info, signer) = prepare_signer(&chain).await?;
    println!(
        "joined {SPAWN_CHAIN_ID} grpc {} rpc {} lcd {}",
        info.grpc_urls.first().map(String::as_str).unwrap_or(""),
        info.rpc_urls.first().map(String::as_str).unwrap_or(""),
        info.lcd_url.as_deref().unwrap_or("")
    );
    println!("funded signer {signer}");
    Ok((chain, info, signer))
}

async fn prepare_signer(chain: &CosmosChain) -> Result<(ChainInfoOwned, String), String> {
    let mnemonic = signer_mnemonic()?;
    chain
        .recover_key("signer", &mnemonic)
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    let signer = chain
        .key_address("signer")
        .await
        .map_err(|err| format!("spawn refused: {err}"))?;
    fund_address(chain, &signer).await?;
    let info = chain_info_from_cosmos(chain).map_err(|err| format!("spawn refused: {err}"))?;
    Ok((info, signer))
}

async fn fund_address(chain: &CosmosChain, address: &str) -> Result<(), String> {
    let sent = chain
        .chain_exec_tx(&[
            "tx",
            "bank",
            "send",
            "validator",
            address,
            SPAWN_FUND,
            "--from",
            "validator",
        ])
        .await
        .map_err(|err| format!("spawn fund refused: {err}"))?;
    if sent.exit_code != 0 {
        return Err(format!("spawn fund refused: {}", sent.stderr_str()));
    }
    wait_for_blocks(chain, 1)
        .await
        .map_err(|err| format!("spawn fund refused: {err}"))?;
    Ok(())
}
