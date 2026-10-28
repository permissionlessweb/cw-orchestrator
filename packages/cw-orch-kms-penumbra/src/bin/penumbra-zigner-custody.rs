//! penumbra-zigner-custody: Zigner-backed Penumbra custody on loopback.
//!
//!   serve      CustodyService gRPC (for a pcli/pclientd patched with a remote
//!              custody backend, or any CustodyServiceClient)
//!   authorize  one plan file (TransactionPlan proto) → AuthorizationData proto file
//!   summary    print what a plan does
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cw_orch_kms_penumbra::{custody, policy::Policy, summary, PinnedAccount};
use penumbra_sdk_proto::DomainType;
use penumbra_sdk_transaction::TransactionPlan;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

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
    #[arg(long, default_value = "127.0.0.1:8743")]
    page: SocketAddr,
    #[arg(long, default_value_t = 600)]
    timeout_secs: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Serve {
        #[arg(long, default_value = "127.0.0.1:8742")]
        grpc: SocketAddr,
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
        #[arg(long, default_value = "127.0.0.1:8742")]
        grpc: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:8744")]
        approval_page: SocketAddr,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Ephemeral homes + pointer file (`current-home`) live here.
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let policy: Policy = match &cli.policy {
        Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
        None => Policy::default(),
    };
    if let Cmd::Session { node, grpc, approval_page, ttl_secs, state_dir } = &cli.cmd {
        let pinned = cli.expect_address.clone().context("--expect-address (the pinned cold wallet) is required for session")?;
        let state_dir = state_dir.clone().unwrap_or_else(|| std::env::temp_dir().join("cw-orch-kms-penumbra"));
        let zxing_js = std::env::var("CW_ORCH_KMS_ZXING").ok().and_then(|p| std::fs::read(p).ok());
        let r = cw_orch_kms_penumbra::session::start(cw_orch_kms_penumbra::session::SessionConfig {
            pinned_address: pinned,
            policy,
            node_grpc_url: node.clone(),
            page: cli.page,
            custody: *grpc,
            approval_page: *approval_page,
            ttl: Duration::from_secs(*ttl_secs),
            approval_timeout: Duration::from_secs(cli.timeout_secs),
            state_dir: state_dir.clone(),
            zxing_js,
        })
        .await?;
        eprintln!("open {} and scan Zigner's FVK export (session TTL {}s)", r.page_url, ttl_secs);
        eprintln!("after import:  pcli --home \"$(cat {}/current-home)\" view balance", state_dir.display());
        return r.done.await?;
    }
    let fvk = std::fs::read_to_string(cli.fvk_file.as_ref().context("--fvk-file required")?).context("reading fvk file")?;
    let account = PinnedAccount::new(&fvk, cli.expect_address.as_deref())?;
    eprintln!("pinned wallet {}", account.wallet_id());
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
            let c = custody::ZignerCustody::new(account, policy, cli.page, Duration::from_secs(cli.timeout_secs))?;
            let data = c.authorize_plan(&plan).await?;
            std::fs::write(&out, data.encode_to_vec())?;
            eprintln!("verified; AuthorizationData written to {}", out.display());
        }
        Cmd::Serve { grpc } => {
            let c = custody::ZignerCustody::new(account, policy, cli.page, Duration::from_secs(cli.timeout_secs))?;
            eprintln!("custody gRPC on {grpc}, approval pages on {}", cli.page);
            custody::serve(c, grpc).await?;
        }
        Cmd::Session { .. } => unreachable!(),
    }
    Ok(())
}
