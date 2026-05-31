use cosmwasm_std::StdResult;
use cw_orch::daemon::networks::{ARCHWAY_1, OSMOSIS_1};
use cw_orch_interchain::prelude::*;

fn follow_by_tx_hash() -> StdResult<()> {
    dotenv::dotenv()?;

    let dst_chain = ARCHWAY_1;
    let src_chain = OSMOSIS_1;

    let interchain = DaemonInterchain::new(
        vec![src_chain.clone(), dst_chain],
        &ChannelCreationValidator,
    )?;

    interchain
        .await_packets_for_txhash(
            src_chain.chain_id,
            "D2C5459C54B394C168B8DFA214670FF9E2A0349CCBEF149CF5CB508A5B3BCB84".to_string(),
        )?
        .assert()?;

    Ok(())
}

fn main() {
    env_logger::init();
    follow_by_tx_hash().unwrap();
}
