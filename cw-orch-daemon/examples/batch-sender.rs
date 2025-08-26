use cosmwasm_std::StdResult;
use counter_contract::{
    msg::InstantiateMsg, CounterContract, CounterExecuteMsgFns, CounterQueryMsgFns,
};
use cw_orch::{anyhow, daemon::senders::BatchDaemon, prelude::*};
use cw_orch_daemon::senders::CosmosBatchOptions;

// From https://github.com/CosmosContracts/juno/blob/32568dba828ff7783aea8cb5bb4b8b5832888255/docker/test-user.env#L2
const LOCAL_MNEMONIC: &str = "clip hire initial neck maid actor venue client foam budget lock catalog sweet steak waste crater broccoli pipe steak sister coyote moment obvious choose";
pub fn main() -> StdResult<()> {
    std::env::set_var("LOCAL_MNEMONIC", LOCAL_MNEMONIC);
    dotenv::dotenv().ok(); // Used to load the `.env` file if any
    pretty_env_logger::init(); // Used to log contract and chain interactions

    let network = networks::LOCAL_JUNO;
    let chain: BatchDaemon =
        BatchDaemon::builder(network).build_sender(CosmosBatchOptions::default())?;

    let counter = CounterContract::new(chain.clone());

    counter.upload()?;
    counter.instantiate(&InstantiateMsg { count: 0 }, None, &[])?;

    counter.increment()?;

    // The count hasn't been incremented yet, we didn't broadcast the tx
    let count = counter.get_count()?;
    assert_eq!(count.count, 0);

    chain.rt_handle.block_on(chain.sender().broadcast(None))?;

    let count = counter.get_count()?;
    assert_eq!(count.count, 1);

    // Increment multiple times in the same transaction
    counter.increment()?;
    counter.increment()?;
    counter.increment()?;
    counter.increment()?;
    counter.increment()?;
    counter.increment()?;

    chain.rt_handle.block_on(chain.sender().broadcast(None))?;

    let count = counter.get_count()?;
    assert_eq!(count.count, 7);

    Ok(())
}
