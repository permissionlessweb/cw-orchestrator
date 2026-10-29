//! Approval-page ports. Every page binds 127.0.0.1 only. With no override a
//! process picks one random port in [`PORT_RANGE`], keeps it for every page it
//! opens, and moves to another random port when the one it wants is taken, so
//! parallel runs never block on a shared fixed port.
//!
//! `CW_ORCH_KMS_PORT=<port>` pins the port (no retry: a taken fixed port is an error).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener as StdListener};
use std::ops::RangeInclusive;
use std::sync::Mutex;

use rand::Rng;

/// Env var that pins the cw-orch-kms approval page port.
pub const PORT_ENV: &str = "CW_ORCH_KMS_PORT";
/// Random ports come from here (clear of the old fixed 8741-8744).
pub const PORT_RANGE: RangeInclusive<u16> = 18700..=18999;
const MAX_TRIES: usize = 64;

static PINNED: Mutex<Option<u16>> = Mutex::new(None);

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// The port pinned by `env`, if set. A set but unparsable value is an error.
pub fn env_port(env: &str) -> Result<Option<u16>, String> {
    match std::env::var(env) {
        Ok(raw) if !raw.trim().is_empty() => raw
            .trim()
            .parse::<u16>()
            .map(Some)
            .map_err(|err| format!("{env}={raw:?} is not a port: {err}")),
        _ => Ok(None),
    }
}

/// A random loopback port in [`PORT_RANGE`] that is free right now (not `avoid`).
/// Falls back to an OS-assigned port when the range looks full.
pub fn free_port(avoid: Option<u16>) -> u16 {
    let mut rng = rand::thread_rng();
    for _ in 0..MAX_TRIES {
        let port = rng.gen_range(PORT_RANGE);
        if Some(port) == avoid {
            continue;
        }
        if StdListener::bind(loopback(port)).is_ok() {
            return port;
        }
    }
    StdListener::bind(loopback(0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(0)
}

/// `127.0.0.1:<port>` from `env`, else a fresh random free port.
pub fn loopback_addr_from_env(env: &str) -> Result<SocketAddr, String> {
    Ok(loopback(match env_port(env)? {
        Some(port) => port,
        None => free_port(None),
    }))
}

/// This process's approval page address: `CW_ORCH_KMS_PORT`, else one random
/// port picked on first use and reused by every later page in the process.
pub fn page_addr() -> SocketAddr {
    match env_port(PORT_ENV) {
        Ok(Some(port)) => return loopback(port),
        Ok(None) => {}
        Err(err) => panic!("{err}"),
    }
    let mut pinned = PINNED.lock().unwrap_or_else(|p| p.into_inner());
    loopback(*pinned.get_or_insert_with(|| free_port(None)))
}

fn may_repick(port: u16) -> bool {
    PORT_RANGE.contains(&port) && !matches!(env_port(PORT_ENV), Ok(Some(p)) if p == port)
}

/// Bind a loopback listener. A random-range port that is taken is replaced by
/// another random port (the process pin follows it). Prints the page URL and
/// the SSH tunnel line.
pub async fn bind_loopback(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    let listener = bind_loopback_quiet(addr).await?;
    if let Ok(bound) = listener.local_addr() {
        announce("approval page", bound);
    }
    Ok(listener)
}

/// [`bind_loopback`] without the printout.
pub async fn bind_loopback_quiet(addr: SocketAddr) -> Result<tokio::net::TcpListener, String> {
    if !addr.ip().is_loopback() {
        return Err(format!("terminal refused: bind {addr} is not loopback"));
    }
    let mut want = addr;
    let mut tries = 0;
    loop {
        match tokio::net::TcpListener::bind(want).await {
            Ok(listener) => {
                if want.port() != addr.port() {
                    let mut pinned = PINNED.lock().unwrap_or_else(|p| p.into_inner());
                    if *pinned == Some(addr.port()) {
                        *pinned = Some(want.port());
                    }
                    eprintln!("port {} was taken; using {}", addr.port(), want.port());
                }
                return Ok(listener);
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::AddrInUse
                    && may_repick(addr.port())
                    && tries < MAX_TRIES =>
            {
                tries += 1;
                want = loopback(free_port(Some(want.port())));
            }
            Err(err) => return Err(format!("terminal bind refused: {want}: {err}")),
        }
    }
}

/// Print `label: http://127.0.0.1:PORT/` and the tunnel command for it.
pub fn announce(label: &str, bound: SocketAddr) {
    let port = bound.port();
    println!("{label}: http://127.0.0.1:{port}/");
    println!("  tunnel: ssh -N -L {port}:127.0.0.1:{port} <this-host>   (then open http://127.0.0.1:{port}/ locally)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_addr_is_loopback_in_range_and_pinned() {
        if std::env::var(PORT_ENV).is_ok() {
            return;
        }
        let a = page_addr();
        assert!(a.ip().is_loopback());
        assert!(PORT_RANGE.contains(&a.port()));
        assert_eq!(a, page_addr());
    }

    #[tokio::test]
    async fn taken_random_port_is_repicked() {
        let squat = StdListener::bind(loopback(free_port(None))).unwrap();
        let taken = squat.local_addr().unwrap();
        if !PORT_RANGE.contains(&taken.port()) {
            return;
        }
        let l = bind_loopback_quiet(taken).await.unwrap();
        let got = l.local_addr().unwrap();
        assert_ne!(got.port(), taken.port());
        assert!(got.ip().is_loopback());
    }

    #[tokio::test]
    async fn taken_explicit_port_outside_range_errors() {
        let squat = StdListener::bind(loopback(0)).unwrap();
        let taken = squat.local_addr().unwrap();
        if PORT_RANGE.contains(&taken.port()) {
            return;
        }
        assert!(bind_loopback_quiet(taken).await.is_err());
    }

    #[tokio::test]
    async fn non_loopback_refused() {
        assert!(bind_loopback_quiet("0.0.0.0:0".parse().unwrap()).await.is_err());
    }
}
