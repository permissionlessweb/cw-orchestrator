use std::{cell::RefCell, rc::Rc};

use cosmwasm_std::{Addr, Coin};
use cw_orch_core::{
    environment::{BankQuerier, Querier, QuerierGetter, StateInterface},
    CwEnvError,
};

use crate::{core::CloneTestingApp, CloneTesting};

pub struct CloneBankQuerier {
    app: Rc<RefCell<CloneTestingApp>>,
}

impl CloneBankQuerier {
    fn new<S: StateInterface>(mock: &CloneTesting<S>) -> Self {
        Self {
            app: mock.app.clone(),
        }
    }
}

impl<S: StateInterface> QuerierGetter<CloneBankQuerier> for CloneTesting<S> {
    fn querier(&self) -> CloneBankQuerier {
        CloneBankQuerier::new(self)
    }
}

impl Querier for CloneBankQuerier {
    type Error = CwEnvError;
}

impl BankQuerier for CloneBankQuerier {
    fn balance(
        &self,
        address: &Addr,
        denom: Option<String>,
    ) -> Result<Vec<cosmwasm_std::Coin>, Self::Error> {
        if let Some(denom) = denom {
            let amount = self
                .app
                .borrow()
                .wrap()
                .query_balance(address, denom.clone())?
                .amount;
            Ok(vec![Coin { amount, denom }])
        } else {
            Err(CwEnvError::StdErr("you must provide a coin denomination to query a balance for. We currently cannot query for all of the uses balances, due to support of this function being removed in cosmwasm@v3.0.0".into()))
        }
    }

    fn supply_of(&self, denom: impl Into<String>) -> Result<cosmwasm_std::Coin, Self::Error> {
        Ok(self.app.borrow().wrap().query_supply(denom)?)
    }

    fn total_supply(&self) -> Result<Vec<cosmwasm_std::Coin>, Self::Error> {
        unimplemented!()
    }
}
