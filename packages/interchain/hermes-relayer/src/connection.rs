//! Script-driven client + connection handshake. No hermes daemon: the
//! in-process ibc-relayer library builds and submits every message with the
//! relayer key from `TEST_MNEMONIC`.
use std::time::Duration;

use crate::core::HermesRelayer;
use cw_orch_interchain_core::env::ChainId;
use ibc_relayer::connection::Connection;
use ibc_relayer::foreign_client::ForeignClient;
use ibc_relayer_cli::cli_utils::ChainHandlePair;
use ibc_relayer_types::core::ics24_host::identifier;

impl HermesRelayer {
    /// Create a light client on each side and run the connection handshake.
    /// Records the connection ids in both directions so
    /// [`cw_orch_interchain_daemon::ChannelCreator::create_ibc_channel`] can
    /// open a channel on top. Returns (connection on `a`, connection on `b`).
    pub fn create_connection(&mut self, a: ChainId, b: ChainId) -> anyhow::Result<(String, String)> {
        let config = self.duplex_config(a, b);
        let chains = ChainHandlePair::spawn(
            &config,
            &identifier::ChainId::from_string(a),
            &identifier::ChainId::from_string(b),
        )
        .map_err(|e| anyhow::anyhow!("spawn chain runtimes: {e}"))?;
        self.add_key(&chains.src);
        self.add_key(&chains.dst);
        // client hosted on a, tracking b; and the reverse
        let on_a = ForeignClient::new(chains.src.clone(), chains.dst.clone())
            .map_err(|e| anyhow::anyhow!("client on {a}: {e}"))?;
        let on_b = ForeignClient::new(chains.dst.clone(), chains.src.clone())
            .map_err(|e| anyhow::anyhow!("client on {b}: {e}"))?;
        log::info!("clients: {} on {a}, {} on {b}", on_a.id(), on_b.id());
        let conn = Connection::new(on_a, on_b, Duration::ZERO)
            .map_err(|e| anyhow::anyhow!("connection handshake: {e}"))?;
        let ca = conn
            .src_connection_id()
            .ok_or_else(|| anyhow::anyhow!("no connection id on {a}"))?
            .to_string();
        let cb = conn
            .dst_connection_id()
            .ok_or_else(|| anyhow::anyhow!("no connection id on {b}"))?
            .to_string();
        self.connection_ids.insert((a.to_string(), b.to_string()), ca.clone());
        self.connection_ids.insert((b.to_string(), a.to_string()), cb.clone());
        Ok((ca, cb))
    }
}
