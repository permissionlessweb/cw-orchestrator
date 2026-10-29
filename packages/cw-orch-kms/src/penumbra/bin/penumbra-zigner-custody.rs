//! penumbra-zigner-custody: Zigner-backed Penumbra custody on loopback.
//!
//!   serve      CustodyService gRPC (for a pcli/pclientd patched with a remote
//!              custody backend, or any CustodyServiceClient)
//!   session    view+sign session: FVK imported from Zigner, wiped on exit
//!
//! Every mode uses one page (`--page`, the shared cw-orch-kms page) for the
//! phone. Build from packages/cw-orch-kms/penumbra (cargo build --release).
//!   authorize  one plan file (TransactionPlan proto) → AuthorizationData proto file
//!   summary    print what a plan does
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cw_orch_kms_penumbra::port;
use cw_orch_kms_penumbra::penumbra::{custody, page, policy::Policy, session, summary, PinnedAccount};
use penumbra_sdk_proto::DomainType;
use penumbra_sdk_transaction::TransactionPlan;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

const PAGE_PORT_ENV: &str = "CW_ORCH_KMS_PENUMBRA_PAGE_PORT";
const GRPC_PORT_ENV: &str = "CW_ORCH_KMS_PENUMBRA_GRPC_PORT";

#[derive(Parser)]
struct Cli {
    /// File holding the pinned bech32m full viewing key (never a spend key).
    /// (serve/authorize/summary) pinned FVK file. Not used by `session`,
    /// which imports the FVK from Zigner's QR and keeps it in memory.
    #[arg(long)]
    fvk_file: Option<PathBuf>,
    /// Optional address that must belong to the FVK (pin check).
    #[arg(long)]
    expect_address: Option<String>,
    /// Policy JSON (see policy::Policy); default: ics20 + LP + spends/outputs to self.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Page address (loopback). Default: env CW_ORCH_KMS_PENUMBRA_PAGE_PORT,
    /// else a random free port in 18700-18999 (re-picked if taken).
    #[arg(long)]
    page: Option<SocketAddr>,
    #[arg(long, default_value_t = 600)]
    timeout_secs: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Serve {
        /// Default: env CW_ORCH_KMS_PENUMBRA_GRPC_PORT, else random 18700-18999.
        #[arg(long)]
        grpc: Option<SocketAddr>,
    },
    Authorize {
        plan: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Summary {
        plan: PathBuf,
    },
    /// Time-limited cold-wallet view+sign session (FVK imported from Zigner QR).
    Session {
        /// Node pcli syncs from (read-only), e.g. https://penumbra-grpc.bryanlabs.net
        #[arg(long)]
        node: String,
        /// Default: env CW_ORCH_KMS_PENUMBRA_GRPC_PORT, else random 18700-18999.
        #[arg(long)]
        grpc: Option<SocketAddr>,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Ephemeral homes + pointer file (`current-home`) live here.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let page_addr = match cli.page {
        Some(a) => a,
        None => port::loopback_addr_from_env(PAGE_PORT_ENV).map_err(anyhow::Error::msg)?,
    };
    let grpc_or_env = |g: Option<SocketAddr>| -> Result<SocketAddr> {
        match g {
            Some(a) => Ok(a),
            None => port::loopback_addr_from_env(GRPC_PORT_ENV).map_err(anyhow::Error::msg),
        }
    };
    let policy: Policy = match &cli.policy {
        Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
        None => Policy::default(),
    };
    if let Cmd::Session { node, grpc, ttl_secs, state_dir } = &cli.cmd {
        let pinned = cli.expect_address.clone().context("--expect-address (the pinned cold wallet) is required for session")?;
        let state_dir = state_dir.clone().unwrap_or_else(|| std::env::temp_dir().join("cw-orch-kms-penumbra"));
        let r = session::start(session::SessionConfig {
            pinned_address: pinned,
            policy,
            node_grpc_url: node.clone(),
            page: page_addr,
            custody: grpc_or_env(*grpc)?,
            ttl: Duration::from_secs(*ttl_secs),
            approval_timeout: Duration::from_secs(cli.timeout_secs),
            state_dir: state_dir.clone(),
        })
        .await?;
        println!("open {} and scan Zigner's FVK export (session TTL {}s)", r.page_url, ttl_secs);
        println!("after import:  pcli --home \"$(cat {}/current-home)\" view balance", state_dir.display());
        return r.done.await?;
    }
    let fvk = std::fs::read_to_string(cli.fvk_file.as_ref().context("--fvk-file required")?).context("reading fvk file")?;
    let account = PinnedAccount::new(&fvk, cli.expect_address.as_deref())?;
    println!("pinned wallet {}", account.wallet_id());
    let read_plan = |p: &PathBuf| -> Result<TransactionPlan> { TransactionPlan::decode(std::fs::read(p)?.as_slice()) };
    match cli.cmd {
        Cmd::Summary { plan } => {
            let plan = read_plan(&plan)?;
            print!("{}", summary::summarize(&plan, &account.fvk).to_text());
            if let Err(e) = policy.check(&plan, &account.fvk) {
                println!("policy: REFUSE ({e:#})");
            } else {
                println!("policy: ok");
            }
        }
        Cmd::Authorize { plan, out } => {
            let plan = read_plan(&plan)?;
            let approvals = page::Approvals::new();
            let (url, stop, srv) = page::serve(page_addr, page::router(approvals.clone(), None, axum::Router::new())).await?;
            println!("approval page {url}");
            let c = custody::ZignerCustody::new(account, policy, approvals, Duration::from_secs(cli.timeout_secs));
            let data = c.authorize_plan(&plan).await;
            let _ = stop.send(());
            let _ = srv.await;
            let data = data?;
            std::fs::write(&out, data.encode_to_vec())?;
            println!("ok verified; AuthorizationData written to {}", out.display());
        }
        Cmd::Serve { grpc } => {
            let approvals = page::Approvals::new();
            let (url, _stop, _srv) = page::serve(page_addr, page::router(approvals.clone(), None, axum::Router::new())).await?;
            let c = custody::ZignerCustody::new(account, policy, approvals, Duration::from_secs(cli.timeout_secs));
            let listener = port::bind_loopback_quiet(grpc_or_env(grpc)?).await.map_err(anyhow::Error::msg)?;
            println!("custody gRPC on {}, approval page {url}", listener.local_addr()?);
            custody::serve_listener(c, listener).await?;
        }
        Cmd::Session { .. } => unreachable!(),
    }
    Ok(())
}
