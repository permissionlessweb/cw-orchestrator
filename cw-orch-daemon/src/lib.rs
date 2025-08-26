// TODO: Figure out better mutex locking for senders
#![allow(clippy::await_holding_lock)]
//! `Daemon` and `DaemonAsync` execution environments.
//!
//! The `Daemon` type is a synchronous wrapper around the `DaemonAsync` type and can be used as a contract execution environment.
pub mod json_lock;
/// Proto types for different blockchains
pub mod proto;
// expose these as mods as they can grow
pub mod env;
pub mod keys;
pub mod live_mock;
pub mod queriers;
pub mod senders;
pub mod tx_broadcaster;
pub mod tx_builder;

mod builder;
mod channel;
mod core;
mod error;
mod log;
mod network_config;
mod state;
mod sync;
mod tx_resp;

pub use self::{builder::*, channel::*, core::*, error::*, state::*, sync::*, tx_resp::*};
pub use cw_orch_networks::networks;
pub use network_config::read_network_config;
pub use senders::{query::QuerySender, tx::TxSender, CosmosOptions, Wallet};
pub use tx_builder::TxBuilder;

pub(crate) mod cosmos_modules {
    pub use cosmrs::proto::{
        cosmos::{
            auth::v1beta1 as auth,
            authz::v1beta1 as authz,
            bank::v1beta1 as bank,
            base::{abci::v1beta1 as abci, tendermint::v1beta1 as tendermint},
            feegrant::v1beta1 as feegrant,
            gov::v1beta1 as gov,
            staking::v1beta1 as staking,
            tx::v1beta1 as tx,
            vesting::v1beta1 as vesting,
        },
        cosmwasm::wasm::v1 as cosmwasm,
        tendermint::abci as tendermint_abci,
    };
    pub use ibc_proto::ibc::{
        applications::transfer::v1 as ibc_transfer,
        core::{
            channel::v1 as ibc_channel, client::v1 as ibc_client, connection::v1 as ibc_connection,
        },
    };
}

lazy_static::lazy_static! {
    pub static ref RUNTIME: tokio::runtime::Runtime = tokio::runtime::Runtime::new().unwrap();
}
