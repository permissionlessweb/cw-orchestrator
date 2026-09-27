//! Local Terp chain: ict-rs boots the node, cw-orch uploads terp-frost, and
//! `FrostKmsSender` broadcasts a bank send whose signature is the Schnorr quorum.
//!
//! The wasm is built with cosmwasm-std's default `zk` feature, which pulls
//! `hash-blake` and therefore the host import `env.blake3_256`. Tags
//! `v6.3.0-dev` and `v6.3.0-dev-blake3` rejected that import on 2026-09-27.
//! A teammate is rebuilding the image with the current default imports.
//! This test does not strip the import to fit the old image.
//!
//! ```sh
//! TERP_IMAGE_VERSION=<image-with-env.blake3_256> ICT_FROST=1 \
//!   cargo test -p cw-orch-kms --features ict --test local_chain -- --nocapture
//! ```

#![cfg(feature = "ict")]

use std::path::PathBuf;
use cosmrs::cosmwasm::MsgInstantiateContract;
use cw_orch_core::contract::WasmPath;
use cw_orch_core::environment::IndexResponse;
use cw_orch_daemon::senders::builder::SenderBuilder;
use cw_orch_daemon::senders::tx::TxSender;
use cw_orch_daemon::{upload_wasm, DaemonAsyncBuilder};
use cw_orch_kms::{add_authenticator_any, FrostKmsOptions, FrostSession};
use ict_rs::prelude::*;
use ict_rs::testing::env::TestEnv;
use ict_rs_cw_orch::chain_info_from_cosmos;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn wasm_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../terp-rs/contracts/smart-accounts/terp-frost/artifacts/terp_frost.wasm")
}

#[tokio::test]
async fn frost_kms_authorizes_a_bank_send_on_a_local_chain() {
    if std::env::var("ICT_FROST").ok().as_deref() != Some("1") {
        panic!("ICT_FROST=1 is required. This test spawns a local terp node and does not skip.");
    }
    if std::env::var("TERP_IMAGE_VERSION")
        .or_else(|_| std::env::var("ICT_IMAGE_VERSION"))
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        panic!("set TERP_IMAGE_VERSION to the local terpd image tag before this test");
    }
    let wasm = wasm_path();
    if !wasm.is_file() {
        panic!("missing terp-frost wasm at {}", wasm.display());
    }

    let runtime = IctRuntime::Docker(DockerConfig::default())
        .into_backend()
        .await
        .expect("docker runtime");
    let image = std::env::var("TERP_IMAGE_VERSION")
        .or_else(|_| std::env::var("ICT_IMAGE_VERSION"))
        .expect("image version");
    let slug: String = image
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let mut cfg = TestEnv::terp_config();
    cfg.chain_id = format!("kms-{slug}");
    cfg.modify_genesis = Some(Box::new(|_cfg, bytes| {
        let mut g: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| ict_rs::error::IctError::Other(anyhow::anyhow!(e)))?;
        if let Some(p) = g.pointer_mut("/app_state/smartaccount/params") {
            p["maximum_unauthenticated_gas"] = serde_json::json!(2_000_000);
        }
        serde_json::to_vec(&g).map_err(|e| ict_rs::error::IctError::Other(anyhow::anyhow!(e)))
    }));
    let mut chain = CosmosChain::new(cfg, 1, 0, runtime);
    chain
        .initialize(&TestContext {
            test_name: "frost-kms".into(),
            network_id: String::new(),
        })
        .await
        .expect("initialize");
    chain.start(&[]).await.expect("start chain");
    let result = run_on(&chain, &wasm).await;
    let _ = chain.stop().await;
    result.expect("frost kms local chain");
}

async fn run_on(chain: &CosmosChain, wasm: &std::path::Path) -> Result<(), String> {
    chain
        .recover_key("kms", MNEMONIC)
        .await
        .map_err(|e| e.to_string())?;
    let user = chain
        .primary_node()
        .map_err(|e| e.to_string())?
        .get_key_address("kms")
        .await
        .map_err(|e| e.to_string())?;
    let fund = chain
        .chain_exec_tx(&[
            "tx",
            "bank",
            "send",
            "validator",
            &user,
            "5000000uterp",
            "--from",
            "validator",
        ])
        .await
        .map_err(|e| e.to_string())?;
    if fund.exit_code != 0 {
        return Err(format!("fund {}", fund.stderr_str()));
    }
    wait_for_blocks(chain, 1).await.map_err(|e| e.to_string())?;

    let info = chain_info_from_cosmos(chain).map_err(|e| e.to_string())?;
    let daemon = DaemonAsyncBuilder::new(info)
        .mnemonic(MNEMONIC)
        .is_test(true)
        .load_network(false)
        .deployment_id("frost-kms")
        .build()
        .await
        .map_err(|e| e.to_string())?;
    let stored = upload_wasm(daemon.sender(), WasmPath::new(wasm).map_err(|e| e.to_string())?, None)
        .await
        .map_err(|e| format!("upload {e}"))?;
    let code_id = stored.uploaded_code_id().map_err(|e| e.to_string())?;
    let session = FrostSession::deal(1, 1).map_err(|e| e)?;
    let init = serde_json::json!({
        "group_vk": session.group_vk(),
        "t": 1,
        "n": 1,
        "seats": ["desk"],
    });
    let instantiate = MsgInstantiateContract {
        sender: daemon.sender().msg_sender().map_err(|e| e.to_string())?,
        admin: None,
        code_id,
        label: Some("terp-frost-kms".into()),
        msg: serde_json::to_vec(&init).map_err(|e| e.to_string())?,
        funds: vec![],
    };
    let instantiated = daemon
        .sender()
        .commit_tx(vec![instantiate], Some("instantiate terp-frost"))
        .await
        .map_err(|e| format!("instantiate {e}"))?;
    let contract = instantiated
        .instantiated_contract_address()
        .map_err(|e| e.to_string())?;
    daemon
        .sender()
        .commit_tx_any(
            vec![add_authenticator_any(
                daemon.sender().address().as_str(),
                contract.as_str(),
            )],
            Some("add frost authenticator"),
        )
        .await
        .map_err(|e| format!("add authenticator {e}"))?;
    wait_for_blocks(chain, 1).await.map_err(|e| e.to_string())?;
    let listed = chain
        .chain_exec(&[
            "query",
            "smartaccount",
            "authenticators",
            daemon.sender().address().as_str(),
            "--output",
            "json",
        ])
        .await
        .map_err(|e| e.to_string())?;
    let parsed: serde_json::Value =
        serde_json::from_str(listed.stdout_str().trim()).unwrap_or(serde_json::Value::Null);
    let authenticator_id = parsed["account_authenticators"]
        .as_array()
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("id"))
        .and_then(|id| id.as_u64())
        .or_else(|| {
            parsed
                .pointer("/account_authenticators/0/id")
                .and_then(|id| id.as_str())
                .and_then(|id| id.parse().ok())
        })
        .ok_or_else(|| format!("no authenticator id in {}", listed.stdout_str()))?;

    let info = chain_info_from_cosmos(chain).map_err(|e| e.to_string())?;
    let options = FrostKmsOptions::from_wallet(daemon.sender(), authenticator_id, session.clone())
        .map_err(|e| e.to_string())?;
    let kms = options
        .build(&std::sync::Arc::new(info))
        .await
        .map_err(|e| e.to_string())?;
    kms.bank_send(
        &daemon.sender().address(),
        &[cosmwasm_std::Coin {
            denom: "uterp".into(),
            amount: 1u128.into(),
        }],
    )
    .await
    .map_err(|e| format!("frost bank send {e}"))?;

    let status = chain
        .query_contract(contract.as_str(), r#"{"status":{}}"#)
        .await
        .map_err(|e| e.to_string())?;
    let group_vk = status
        .pointer("/data/group_vk")
        .or_else(|| status.get("group_vk"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if group_vk != session.group_vk() {
        return Err(format!(
            "group vk {group_vk} != session {}",
            session.group_vk()
        ));
    }
    Ok(())
}
