# Interchain Quickstart

## General Example

### Creating the environment

In order to interact with your environment using IBC capabilities, you first need to create an interchain structure.
In this guide, we will create a mock environment for local testing. [↓Click here, if you want to interact with actual nodes](#with-actual-cosmos-sdk-nodes).

With mock chains, you can create a mock environment simply by specifying chains ids and sender addresses.
For this guide, we will create 2 chains, `juno-1` and `osmosis-1`, with respective address prefixes:

```rust,ignore
 let interchain = MockBech32InterchainEnv::new(vec![("juno-1", "juno"), ("osmosis-1", "osmosis")]);
```

### Interacting with the environment

Now, we will work with interchain accounts (ICA). There is a <a href="https://github.com/confio/cw-ibc-demo" target="_blank">simple implementation of the ICA protocol on Github</a>, and we will use that application with a few simplifications for brevity.

In this protocol, we have 2 smart-contracts that are able to create a connection between them.
The `client` will send IBC messages to the `host` that in turn will execute the messages on its chain.
Let's first create the contracts:

```rust,ignore
let juno = interchain.chain("juno-1")?;
let osmosis = interchain.chain("osmosis-1")?;

let client = Client::new("test:client", juno.clone());
let host = Host::new("test:host", osmosis.clone());

client.upload()?;
host.upload()?;
client.instantiate(&Empty{}, None, None)?;
host.instantiate(&Empty{}, None, None)?;
```

The `Client` and `Host` structures here are [cw-orchestrator Contracts](../contracts/interfaces.md) with registered ibc endpoints. 

<details>
  <summary><strong>Client contract definition</strong> (Click to get the full code)</summary>

```rust,ignore
# use cw_orch::prelude::ContractWrapper;
# use cw_orch::contract::WasmPath;
#[interface(
    simple_ica_controller::msg::InstantiateMsg,
    simple_ica_controller::msg::ExecuteMsg,
    simple_ica_controller::msg::QueryMsg,
    Empty
)]
struct Client;

impl<Chain> Uploadable for Client<Chain> {
    // No wasm needed for this example
    // You would need to get the contract wasm to be able to interact with actual Cosmos SDK nodes
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        unimplemented!("No wasm")
    }
    // Return a CosmWasm contract wrapper with IBC capabilities
    fn wrapper() -> Box<dyn MockContract<Empty>> {
        Box::new(
            ContractWrapper::new_with_empty(
                simple_ica_controller::contract::execute,
                simple_ica_controller::contract::instantiate,
                simple_ica_controller::contract::query,
            )
            .with_ibc(
                simple_ica_controller::ibc::ibc_channel_open,
                simple_ica_controller::ibc::ibc_channel_connect,
                simple_ica_controller::ibc::ibc_channel_close,
                simple_ica_controller::ibc::ibc_packet_receive,
                simple_ica_controller::ibc::ibc_packet_ack,
                simple_ica_controller::ibc::ibc_packet_timeout,
            ),
        )
    }
}
```  

</details>

<details>
  <summary><strong>Host contract definition</strong> (Click to get the full code)</summary>

```rust,ignore
// This is used because the simple_ica_host contract doesn't have an execute endpoint defined 
pub fn host_execute(_: DepsMut, _: Env, _: MessageInfo, _: Empty) -> StdResult<Response> {
    Err(StdError::msg("Execute not implemented for host"))
}

#[interface(
    simple_ica_host::msg::InstantiateMsg,
    Empty,
    simple_ica_host::msg::QueryMsg,
    Empty
)]
struct Host;

impl<Chain> Uploadable for Host<Chain> {
    // No wasm needed for this example
    // You would need to get the contract wasm to be able to interact with actual Cosmos SDK nodes
    fn wasm(_chain: &ChainInfoOwned) -> WasmPath {
        unimplemented!("No wasm")
    }
    // Return a CosmWasm contract wrapper with IBC capabilities
    fn wrapper() -> Box<dyn MockContract<Empty>> {
        Box::new(
            ContractWrapper::new_with_empty(
                host_execute,
                simple_ica_host::contract::instantiate,
                simple_ica_host::contract::query,
            )
            .with_reply(simple_ica_host::contract::reply)
            .with_ibc(
                simple_ica_host::contract::ibc_channel_open,
                simple_ica_host::contract::ibc_channel_connect,
                simple_ica_host::contract::ibc_channel_close,
                simple_ica_host::contract::ibc_packet_receive,
                simple_ica_host::contract::ibc_packet_ack,
                simple_ica_host::contract::ibc_packet_timeout,
            ),
        )
    }
}
```  

</details>

Then, we can create an IBC channel between the two contracts:

```rust,ignore
let channel_receipt: ChannelCreationResult<_> = interchain.create_contract_channel(&client, &host, None, "simple-ica-v2").await?;

// After channel creation is complete, we get the channel id, which is necessary for ICA remote execution
let juno_channel = channel_receipt.interchain_channel.get_chain("juno-1")?.channel.unwrap();
```

This step will also await until all the packets sent during channel creation are relayed. In the case of the ICA contracts, a <a href="https://github.com/confio/cw-ibc-demo/blob/main/contracts/simple-ica-controller/src/ibc.rs#L54" target="_blank">`{"who_am_i":{}}`</a> packet is sent out right after channel creation and allows to identify the calling chain.

Finally, the two contracts can interact like so:

```rust,ignore
/// This broadcasts a transaction on the client
/// It sends an IBC packet to the host
let tx_response = client.send_msgs(
    juno_channel.to_string(), 
    vec![CosmosMsg::Bank(cosmwasm_std::BankMsg::Burn {
            amount: vec![cosmwasm_std::coin(100u128, "uosmo")],
    })],
    None
)?;
```

Now, we need to wait for the IBC execution to take place and the relayers to relay the packets. This will also verify that the IBC execution is successful. This is done through:

```rust,ignore
let packet_lifetime = interchain.await_and_check_packets("juno-1", tx_response).await?;
```

If it was relayed correctly, we can proceed with our application.

With this simple guide, you should be able to test and debug your IBC application in no time.
[Learn more about the implementation and details of the IBC-enabled local testing environment](./integrations/mock.md).

## With actual Cosmos SDK Nodes

You can also create an interchain environment that interacts with actual running chains. Keep in mind in that case that this type of environment doesn't allow channel creation. This step will have to be done manually with external tooling. If you're looking to test your application in a full local test setup, please turn to [↓Starship](#with-starship)

```rust,ignore
    use cw_orch::prelude::*;

{{#include ../../../cw-orch-interchain/examples/doc_daemon.rs:DAEMON_INTERCHAIN_CREATION}}

```

With this setup, you can now resume this quick-start guide from [↑Interacting with the environment](#interacting-with-the-environment).

You can also [learn more about the interchain daemon implementation](./integrations/daemon.md).

## With Starship

You can also create you interchain environment using starship, which allows you to test your application against actual nodes and relayers. This time, an additional setup is necessary.
Check out <a href="https://docs.cosmology.zone/starship" target="_blank">the official Starship Getting Started guide</a> for more details.

Once starship is setup and all the ports forwarded, assuming that starship was run locally, you can execute the following:

```rust,ignore
    use cw_orch::prelude::*;
    
{{#include ../../../cw-orch-interchain/examples/doc_daemon.rs:STARSHIP_INTERCHAIN_CREATION}}
```

This snippet will identify the local Starship setup and initialize all helpers and information needed for interaction using cw-orchestrator.
With this setup, you can now resume this quick-start guide from [↑Interacting with the environment](#interacting-with-the-environment)

You can also [learn more about the interchain daemon implementation](./integrations/daemon.md).
