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
    #[arg(long)]
    fvk_file: PathBuf,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let cli = Cli::parse();
    let fvk = std::fs::read_to_string(&cli.fvk_file).context("reading fvk file")?;
    let account = PinnedAccount::new(&fvk, cli.expect_address.as_deref())?;
    let policy: Policy = match &cli.policy {
        Some(p) => serde_json::from_slice(&std::fs::read(p)?)?,
        None => Policy::default(),
    };
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
    }
    Ok(())
}
