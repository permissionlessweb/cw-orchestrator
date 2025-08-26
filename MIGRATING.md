# Migrating cw-orch

This guide explains how to upgrade cw-orch in your contracts.

## cw-orch-core 2.x.x -> 3.x.x (Cosmwasm 3.0)
- Update cw-orch dependencies

    ```diff
    ```
- Update cosmwasm dependencies

    ```diff
    ```
- Update cosmwasm specifications dependencies


    ```diff
    ```
- Update prost dependencies to 0.14.x

    ```diff
    -prost = { version = "0.13.1", default-features = false }
    +prost = { version = "0.14.1", default-features = false }
    ```
- Update cosmos-sdk-proto dependency to 0.28+

    ```diff
    ```


## cw-orch-core 1.x.x -> 2.x.x (Cosmwasm 2.0)

- Update cw-orch dependencies

    ```diff
    -cw-orch = { version = "0.24.0" }
    -cw-orch-interchain = { version = "0.3.0" }
    +cw-orch = { version = "0.25.0" }
    +cw-orch-interchain = { version = "0.4.0" }
    ```

- Update cosmwasm dependencies

    ```diff
    -cosmwasm-std = { version = "1.5.0", features = ["cosmwasm_1_2"] }
    -cosmwasm-schema = { version = "1.2" }
    -cw-controllers = { version = "1.0" }
    -cw-storage-plus = "1.2.0"
    +cosmwasm-std = { version = "2.0.0", features = ["cosmwasm_1_2"] }
    +cosmwasm-schema = { version = "2.0" }
    +cw-controllers = { version = "2.0" }
    +cw-storage-plus = "2.0.0"
    ```

    For more detailed cosmwasm migration see: <https://github.com/CosmWasm/cosmwasm/blob/main/MIGRATING.md#15x---20x>

- Update cosmwasm specifications dependencies

    ```diff
    -cw2 = { version = "1.0" }
    -cw20 = { version = "1.0" }
    +cw2 = { version = "2.0" }
    +cw20 = { version = "2.0" }
    ```

- Update prost dependencies to 0.13.x

    ```diff
    -prost = { version = "0.12.3", default-features = false }
    +prost = { version = "0.13.1", default-features = false }
    ```

- Update cosmos-sdk-proto dependency to 0.24+

    ```diff
    -cosmos-sdk-proto = { version = "0.20.0", default-features = false }
    +cosmos-sdk-proto = { version = "0.24.0", default-features = false }
    +ibc-proto = { version = "0.47.0" } # ibc types from cosmos-sdk-proto replaced by `ibc-proto` package
    ```

- `TxHandler::sender()` was deprecated in 1.1.2 and in 2.x.x versions returned value is `&TxHandler::Sender`, instead of `Addr`, for address please use `TxHandler::sender_addr()`

    ```diff
    -let sender_addr = chain.sender();
    +let sender_addr = chain.sender_addr();
    ```

- Methods from `cw_orch::prelude::Deploy` trait that was related to the daemon state is now inside `cw_orch::daemon::DeployedChains` (feature `daemon` required)
