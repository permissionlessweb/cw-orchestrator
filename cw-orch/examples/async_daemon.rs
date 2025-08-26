use cosmwasm_std::StdResult;
use counter_contract::AsyncCounterQueryMsgFns;
use counter_contract::CounterContract;

use cw_orch_daemon::DaemonAsync;
/// In order to use this script, you need to set the following env variables
///
/// RUST_LOG (recommended value `info`) to see the app logs
///
/// TEST_MNEMONIC to be able to sign and broadcast a transaction on UNI testnet
#[tokio::main]
pub async fn main() -> StdResult<()> {
    // We start by loading environment variables from a .env file.
    // You can use a .env file to specify environment variables.
    // You have an overview of all supported environment variables here : https://orchestrator.abstract.money/contracts/env-variable.html
    dotenv::dotenv().unwrap();

    // We initialize the env logger to be able to see what's happening during the script execution
    // Remember to set the `RUST_LOG` env variable to be able to see the execution
    env_logger::init();

    // We can now create a daemon. This daemon will be used to interact with the chain.
    // In the background, the `build` function uses the `TEST_MNEMONIC` variable, don't forget to set it !
    let daemon = DaemonAsync::builder(cw_orch::daemon::networks::UNI_6) // set the network to use
        .build()
        .await?;

    // Uploading a contract is very simple
    let counter = CounterContract::new(daemon.clone());
    let upload_res = daemon.upload(&counter).await;
    assert!(upload_res.is_ok());

    let count = counter.get_count_async().await?;
    assert_eq!(count.count, 1);

    Ok(())
}
