#![allow(non_snake_case)]

use cw_orch_interchain_core::{
    channel::InterchainChannel, IbcQueryHandler, InterchainEnv, InterchainError, NestedPacketsFlow,
};
use ibc_proto::ibc::apps::transfer::v1::MsgTransfer;
use osmosis_std::types::osmosis::tokenfactory::v1beta1::{MsgCreateDenom, MsgMint};
use prost::{Message, Name};
use tonic::transport::Channel;

use cosmwasm_std::{Coin, StdResult};
use cw_orch_core::environment::{CwEnv, TxHandler};
use cw_orch_traits::FullNode;
use ibc_relayer_types::core::ics24_host::identifier::PortId;

/// Creates a new denom using the token factory module.
///
/// This is used mainly for tests, but feel free to use that in production as well
pub fn create_denom<Chain: FullNode>(
    chain: &Chain,
    token_name: &str,
) -> Result<(), <Chain as TxHandler>::Error> {
    let creator = chain.sender_addr().to_string();

    let any = MsgCreateDenom {
        sender: creator,
        subdenom: token_name.to_string(),
    }
    .to_any();

    chain.commit_any(vec![any.into()], None)?;

    log::info!("Created denom {}", get_denom(chain, token_name));

    Ok(())
}

/// Gets the denom of a token created by a daemon object
///
/// This actually creates the denom for a token created by an address (which is here taken to be the daemon sender address)
/// This is mainly used for tests, but feel free to use that in production as well
pub fn get_denom<Chain: CwEnv>(daemon: &Chain, token_name: &str) -> String {
    let sender = daemon.sender_addr().to_string();
    format!("factory/{}/{}", sender, token_name)
}

/// Mints new subdenom token for which the minter is the sender of chain object
///
/// This mints new tokens to the receiver address
/// This is mainly used for tests, but feel free to use that in production as well
pub fn mint<Chain: FullNode>(
    chain: &Chain,
    receiver: &str,
    token_name: &str,
    amount: u128,
) -> Result<(), <Chain as TxHandler>::Error> {
    let sender = chain.sender_addr().to_string();
    let denom = get_denom(chain, token_name);

    let any = MsgMint {
        sender,
        mint_to_address: receiver.to_string(),
        amount: Some(osmosis_std::types::cosmos::base::v1beta1::Coin {
            denom,
            amount: amount.to_string(),
        }),
    }
    .to_any();

    chain.commit_any(vec![any.into()], None)?;

    log::info!("Minted coins {} {}", amount, get_denom(chain, token_name));

    Ok(())
}

// 1 hour should be sufficient for packet timeout
const TIMEOUT_IN_NANO_SECONDS: u64 = 3_600_000_000_000;

/// Ibc token transfer
///
/// This allows transfering token over a channel using an interchain_channel object
#[allow(clippy::too_many_arguments)]
pub fn transfer_tokens<Chain: IbcQueryHandler + FullNode, IBC: InterchainEnv<Chain>>(
    origin: &Chain,
    receiver: &str,
    fund: &Coin,
    interchain_env: &IBC,
    ibc_channel: &InterchainChannel<Channel>,
    timeout: Option<u64>,
    memo: Option<String>,
) -> Result<NestedPacketsFlow<Chain>, InterchainError> {
    let chain_id = origin.block_info().unwrap().chain_id;

    let (source_port, _) = ibc_channel.get_ordered_ports_from(&chain_id)?;

    let msg_transfer = MsgTransfer {
        source_port: source_port.port.to_string(),
        source_channel: source_port.channel.unwrap().to_string(),
        token: Some(ibc_proto::cosmos::base::v1beta1::Coin {
            amount: fund.amount.to_string(),
            denom: fund.denom.clone(),
        }),
        sender: origin.sender_addr().to_string(),
        receiver: receiver.to_string(),
        timeout_height: None,
        timeout_timestamp: origin.block_info().unwrap().time.nanos()
            + timeout.unwrap_or(TIMEOUT_IN_NANO_SECONDS),
        memo: memo.unwrap_or_default(),
    };

    // We send tokens using the ics20 message over the channel that is passed as an argument
    let send_tx = origin
        .commit_any(
            vec![prost_types::Any {
                type_url: MsgTransfer::full_name(),
                value: msg_transfer.encode_to_vec(),
            }],
            None,
        )
        .unwrap();

    // We wait for the IBC tx to stop successfully
    let tx_results = interchain_env
        .await_packets(&source_port.chain_id, send_tx)
        .unwrap();

    Ok(tx_results)
}

const ICS20_CHANNEL_VERSION: &str = "ics20-1";
/// Channel creation between the transfer channels of two blockchains of a starship integration
pub fn create_transfer_channel<Chain: IbcQueryHandler, IBC: InterchainEnv<Chain>>(
    chain1: &str,
    chain2: &str,
    interchain: &IBC,
) -> StdResult<InterchainChannel<<Chain as IbcQueryHandler>::Handler>> {
    let creation = interchain
        .create_channel(
            chain1,
            chain2,
            &PortId::transfer(),
            &PortId::transfer(),
            ICS20_CHANNEL_VERSION,
            Some(cosmwasm_std::IbcOrder::Unordered),
        )
        .unwrap();

    Ok(creation.interchain_channel)
}
