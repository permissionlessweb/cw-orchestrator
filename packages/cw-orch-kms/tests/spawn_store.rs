//! One authz store on a spawned Terp node.
//!
//! ```sh
//! TERP_IMAGE_REPO=terp-core TERP_IMAGE_VERSION=local-arm64 ICT_SPAWN_STORE=1 \
//!   cargo test -p cw-orch-kms --features ict --test spawn_store -- --nocapture
//! ```

#![cfg(feature = "ict")]

use std::path::PathBuf;

use cosmrs::cosmwasm::MsgStoreCode;
use cw_orch_daemon::senders::tx::TxSender;
use cw_orch_daemon::DaemonAsyncBuilder;
use ict_rs::prelude::*;
use ict_rs::testing::env::TestEnv;
use ict_rs_cw_orch::chain_info_from_cosmos;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn wasm_path() -> PathBuf {
    if let Ok(path) = std::env::var("ICT_SPAWN_WASM") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../dao-contracts/artifacts/dao_dao_core.wasm")
}

#[tokio::test]
async fn authz_feegrant_store_survives_grpc() {
    if std::env::var("ICT_SPAWN_STORE").ok().as_deref() != Some("1") {
        return;
    }
    let wasm = wasm_path();
    assert!(wasm.is_file(), "missing {}", wasm.display());

    let runtime = IctRuntime::Docker(DockerConfig::default())
        .into_backend()
        .await
        .expect("docker runtime");
    let mut cfg = TestEnv::terp_config();
    cfg.chain_id = "storeprobe-1".into();
    let mut chain = CosmosChain::new(cfg, 1, 0, runtime);
    chain
        .initialize(&TestContext {
            test_name: "spawn-store".into(),
            network_id: String::new(),
        })
        .await
        .expect("initialize");
    chain.start(&[]).await.expect("start chain");
    let result = run_on(&chain, &wasm).await;
    if let Err(err) = &result {
        eprintln!("store probe failed: {err}");
        let ps = std::process::Command::new("docker")
            .args(["ps", "-a", "--format", "{{.Names}}"])
            .output();
        if let Ok(ps) = ps {
            for name in String::from_utf8_lossy(&ps.stdout).lines() {
                if !name.contains("spawn-store") && !name.contains("storeprobe") {
                    continue;
                }
                let logs = std::process::Command::new("docker")
                    .args(["logs", "--tail", "120", name])
                    .output();
                if let Ok(logs) = logs {
                    eprintln!(
                        "node {name}:\n{}{}",
                        String::from_utf8_lossy(&logs.stdout),
                        String::from_utf8_lossy(&logs.stderr)
                    );
                }
                let _ = std::process::Command::new("docker")
                    .args([
                        "exec",
                        name,
                        "sh",
                        "-c",
                        "grep -n -E 'max-recv|max-send|max_tx_bytes|max_body' /var/cosmos-chain/storeprobe-1/config/app.toml /var/cosmos-chain/storeprobe-1/config/config.toml",
                    ])
                    .status();
                let limits = std::process::Command::new("docker")
                    .args([
                        "exec",
                        name,
                        "sh",
                        "-c",
                        "grep -n -E 'max-recv|max-send|max_tx_bytes|max_body' /var/cosmos-chain/storeprobe-1/config/app.toml /var/cosmos-chain/storeprobe-1/config/config.toml",
                    ])
                    .output();
                if let Ok(limits) = limits {
                    eprintln!(
                        "limits:\n{}{}",
                        String::from_utf8_lossy(&limits.stdout),
                        String::from_utf8_lossy(&limits.stderr)
                    );
                }
                let _ = std::process::Command::new("docker")
                    .args(["cp", &wasm.display().to_string(), &format!("{name}:/tmp/probe.wasm")])
                    .status();
                let cli = std::process::Command::new("docker")
                    .args([
                        "exec",
                        name,
                        "terpd",
                        "tx",
                        "wasm",
                        "store",
                        "/tmp/probe.wasm",
                        "--from",
                        "validator",
                        "--home",
                        "/var/cosmos-chain/storeprobe-1",
                        "--chain-id",
                        "storeprobe-1",
                        "--gas",
                        "auto",
                        "--gas-adjustment",
                        "1.4",
                        "--fees",
                        "8000000uterp",
                        "--broadcast-mode",
                        "sync",
                        "-y",
                        "--output",
                        "json",
                    ])
                    .output();
                if let Ok(cli) = cli {
                    eprintln!(
                        "cli store:\n{}{}",
                        String::from_utf8_lossy(&cli.stdout),
                        String::from_utf8_lossy(&cli.stderr)
                    );
                }
                let chain_log = std::process::Command::new("docker")
                    .args([
                        "exec",
                        name,
                        "sh",
                        "-c",
                        "grep -E 'panic|ERR |error|fatal|wasm|killed' /var/cosmos-chain/storeprobe-1/chain.log | tail -n 60",
                    ])
                    .output();
                if let Ok(chain_log) = chain_log {
                    eprintln!(
                        "chain.log {name}:\n{}{}",
                        String::from_utf8_lossy(&chain_log.stdout),
                        String::from_utf8_lossy(&chain_log.stderr)
                    );
                }
            }
        }
    }
    let _ = chain.stop().await;
    result.expect("authz store");
}

async fn run_on(chain: &CosmosChain, wasm: &std::path::Path) -> Result<(), String> {
    chain
        .recover_key("signer", MNEMONIC)
        .await
        .map_err(|err| err.to_string())?;
    let signer = chain
        .key_address("signer")
        .await
        .map_err(|err| err.to_string())?;
    let validator = chain
        .key_address("validator")
        .await
        .map_err(|err| err.to_string())?;
    let fund = chain
        .chain_exec_tx(&[
            "tx",
            "bank",
            "send",
            "validator",
            &signer,
            "100000000000uterp",
            "--from",
            "validator",
        ])
        .await
        .map_err(|err| err.to_string())?;
    if fund.exit_code != 0 {
        return Err(format!("fund {}", fund.stderr_str()));
    }
    wait_for_blocks(chain, 1)
        .await
        .map_err(|err| err.to_string())?;
    let grant = chain
        .chain_exec_tx(&[
            "tx",
            "authz",
            "grant",
            &signer,
            "generic",
            "--msg-type",
            "/cosmwasm.wasm.v1.MsgStoreCode",
            "--from",
            "validator",
        ])
        .await
        .map_err(|err| err.to_string())?;
    if grant.exit_code != 0 {
        return Err(format!("authz {}", grant.stderr_str()));
    }
    wait_for_blocks(chain, 1)
        .await
        .map_err(|err| err.to_string())?;
    let allowance = chain
        .chain_exec_tx(&[
            "tx",
            "feegrant",
            "grant",
            &validator,
            &signer,
            "--spend-limit",
            "100000000uterp",
            "--from",
            "validator",
        ])
        .await
        .map_err(|err| err.to_string())?;
    if allowance.exit_code != 0 {
        return Err(format!("feegrant {}", allowance.stderr_str()));
    }
    wait_for_blocks(chain, 1)
        .await
        .map_err(|err| err.to_string())?;

    let info = chain_info_from_cosmos(chain).map_err(|err| err.to_string())?;
    let mut daemon = DaemonAsyncBuilder::new(info)
        .mnemonic(MNEMONIC)
        .is_test(true)
        .load_network(false)
        .deployment_id("spawn-store")
        .build()
        .await
        .map_err(|err| err.to_string())?;
    let granter = cosmwasm_std::Addr::unchecked(validator);
    daemon.sender_mut().set_authz_granter(&granter);
    daemon.sender_mut().set_fee_granter(&granter);

    let wasm_bytes = std::fs::read(wasm).map_err(|err| err.to_string())?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &wasm_bytes).map_err(|err| err.to_string())?;
    let store = MsgStoreCode {
        sender: daemon
            .sender()
            .msg_sender()
            .map_err(|err| err.to_string())?,
        wasm_byte_code: gzip.finish().map_err(|err| err.to_string())?,
        instantiate_permission: None,
    };
    daemon
        .sender()
        .commit_tx(vec![store], Some("authz store"))
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}
