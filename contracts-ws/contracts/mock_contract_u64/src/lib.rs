use mock_contract::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg, ThirdReturn};

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError,
    StdResult, Uint256,
};

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> StdResult<Response> {
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg<u64>,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::FirstMessage {} => {
            Ok(Response::new().add_attribute("action", "first message passed"))
        }
        ExecuteMsg::SecondMessage { t: _ } => Err(StdError::msg("Second Message Failed")),
        ExecuteMsg::ThirdMessage { .. } => {
            Ok(Response::new().add_attribute("action", "third message passed"))
        }
        ExecuteMsg::FourthMessage => {
            Ok(Response::new().add_attribute("action", "fourth message passed"))
        }
        ExecuteMsg::FifthMessage => {
            if info.funds.is_empty() {
                return Err(StdError::msg("Coins missing"));
            }
            Ok(Response::new().add_attribute("action", "fourth message passed"))
        }
        ExecuteMsg::SixthMessage(_, _) => {
            Ok(Response::new().add_attribute("action", "sixth message passed"))
        }
        ExecuteMsg::SeventhMessage(amount, denom) => {
            let c = info.funds[0].clone();
            if c.amount != Uint256::new(amount.u128()) && c.denom.ne(&denom) {
                return Err(StdError::msg("Coins don't match message"));
            }
            Ok(Response::new().add_attribute("action", "fourth message passed"))
        }
    }
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, msg: QueryMsg<u64>) -> StdResult<Binary> {
    match msg {
        QueryMsg::FirstQuery {} => to_json_binary("first query passed"),
        QueryMsg::SecondQuery { .. } => Err(StdError::msg("Query not available")),
        QueryMsg::ThirdQuery { .. } => to_json_binary(&ThirdReturn { t: 0u64 }),
        QueryMsg::FourthQuery(_, _) => to_json_binary("fourth query passed"),
    }
}

#[entry_point]
pub fn migrate(_deps: DepsMut, _env: Env, msg: MigrateMsg) -> StdResult<Response> {
    if msg.t.eq("success") {
        Ok(Response::new())
    } else {
        Err(StdError::msg(
            "migrate endpoint reached but no test implementation",
        ))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub mod interface {
    use cw_orch::environment::ChainInfoOwned;

    use super::*;

    #[cw_orch::interface(InstantiateMsg, ExecuteMsg<T>, QueryMsg<Q>, MigrateMsg, id = "mock-contract")]
    pub struct MockContract<Chain, T, Q>;

    impl<Chain> cw_orch::prelude::Uploadable for MockContract<Chain, u64, u64> {
        fn wrapper(
        ) -> Box<dyn cw_orch::prelude::MockContract<cosmwasm_std::Empty, cosmwasm_std::Empty>>
        {
            Box::new(
                cw_orch::prelude::ContractWrapper::new(execute, instantiate, query)
                    .with_migrate(migrate),
            )
        }

        fn wasm(_chain: &ChainInfoOwned) -> cw_orch::prelude::WasmPath {
            use cw_orch::prelude::*;
            artifacts_dir_from_workspace!()
                .find_wasm_path("mock_contract")
                .unwrap()
        }
    }
}

#[cfg(test)]
mod test {
    use super::interface::MockContract as LocalMockContract;
    use super::*;
    use cosmwasm_std::coins;
    use cw_orch::prelude::*;
    use mock_contract::{ExecuteMsgFns, QueryMsgFns};

    #[test]
    fn compiles() -> Result<(), CwOrchError> {
        // We need to check we can still call the execute msgs conveniently
        let mock = Mock::new("sender");
        let sender = mock.sender_addr();
        mock.set_balance(&sender, coins(156 * 2, "ujuno"))?;
        let contract = LocalMockContract::new(mock.clone());

        contract.upload()?;
        contract.instantiate(&InstantiateMsg {}, None, &[])?;
        contract.first_message()?;
        contract.second_message(54u64, &[]).unwrap_err();
        contract.third_message(54u64).unwrap();
        contract.fourth(&[]).unwrap();
        contract.fifth_message(&coins(156, "ujuno")).unwrap();
        contract.sixth_message(45u64, "moneys").unwrap();

        contract
            .seventh_message(156u128, "ujuno", &coins(156, "ujuno"))
            .unwrap();

        contract.first_query().unwrap();
        contract.second_query(45u64).unwrap_err();
        contract.third_query(67u64).unwrap();
        contract.fourth_query(45u64, "moneys").unwrap_err();

        Ok(())
    }
}
