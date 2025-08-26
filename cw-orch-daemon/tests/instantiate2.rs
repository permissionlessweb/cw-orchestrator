mod common;

#[cfg(feature = "node-tests")]
pub mod test {

    use cosmwasm_std::Binary;
    use cw_orch_core::contract::interface_traits::ContractInstance;
    use cw_orch_core::contract::interface_traits::CwOrchInstantiate;
    use cw_orch_core::contract::interface_traits::CwOrchUpload;
    use cw_orch_daemon::Daemon;
    use cw_orch_networks::networks;
    use mock_contract::InstantiateMsg;
    use mock_contract::MockContract;

    #[test]
    #[serial_test::serial]
    fn instantiate2() -> StdResult<()> {
        super::common::enable_logger();
        let app = Daemon::builder(networks::LOCAL_JUNO)
            .is_test(true)
            .build()
            .unwrap();

        let salt = Binary::new(vec![12, 89, 156, 63]);
        let mock_contract = MockContract::new("mock-contract", app.clone());

        mock_contract.upload()?;

        mock_contract.instantiate2(&InstantiateMsg {}, None, &[], salt.clone())?;

        mock_contract.address()?;

        Ok(())
    }
}
