//! Type URLs a Terp wallet can be granted.
//!
//! Cosmos authz stores one generic authorization per message type. This list
//! is the default session: the core sdk 0.55 services Terp registers, ibc-go
//! v11 (client, connection, channel v1 and v2, transfer, interchain accounts,
//! and the wasm light client), wasmd as forked in terp-core, and the Terp
//! modules (Osmosis tokenfactory, feeshare, drip, smartaccount, hashmerchant,
//! globalfee). Group, NFT, IBC fee, GMP, and rate-limit are not registered
//! on this chain, so they are not granted.

/// Message types the chain registers. A session does not grant this list.
/// Name each message the run will send.
pub const WALLET_TYPE_URLS: &[&str] = &[
    "/cosmos.auth.v1beta1.MsgUpdateParams",
    "/cosmos.authz.v1beta1.MsgExec",
    "/cosmos.authz.v1beta1.MsgGrant",
    "/cosmos.authz.v1beta1.MsgRevoke",
    "/cosmos.bank.v1beta1.MsgMultiSend",
    "/cosmos.bank.v1beta1.MsgSend",
    "/cosmos.bank.v1beta1.MsgSetSendEnabled",
    "/cosmos.bank.v1beta1.MsgUpdateParams",
    "/cosmos.consensus.v1.MsgUpdateParams",
    "/cosmos.crisis.v1beta1.MsgUpdateParams",
    "/cosmos.crisis.v1beta1.MsgVerifyInvariant",
    "/cosmos.distribution.v1beta1.MsgCommunityPoolSpend",
    "/cosmos.distribution.v1beta1.MsgDepositValidatorRewardsPool",
    "/cosmos.distribution.v1beta1.MsgFundCommunityPool",
    "/cosmos.distribution.v1beta1.MsgSetWithdrawAddress",
    "/cosmos.distribution.v1beta1.MsgUpdateParams",
    "/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward",
    "/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission",
    "/cosmos.evidence.v1beta1.MsgSubmitEvidence",
    "/cosmos.feegrant.v1beta1.MsgGrantAllowance",
    "/cosmos.feegrant.v1beta1.MsgPruneAllowances",
    "/cosmos.feegrant.v1beta1.MsgRevokeAllowance",
    "/cosmos.gov.v1.MsgCancelProposal",
    "/cosmos.gov.v1.MsgDeposit",
    "/cosmos.gov.v1.MsgExecLegacyContent",
    "/cosmos.gov.v1.MsgSubmitProposal",
    "/cosmos.gov.v1.MsgUpdateParams",
    "/cosmos.gov.v1.MsgVote",
    "/cosmos.gov.v1.MsgVoteWeighted",
    "/cosmos.gov.v1beta1.MsgDeposit",
    "/cosmos.gov.v1beta1.MsgSubmitProposal",
    "/cosmos.gov.v1beta1.MsgVote",
    "/cosmos.gov.v1beta1.MsgVoteWeighted",
    "/cosmos.mint.v1beta1.MsgUpdateParams",
    "/cosmos.slashing.v1beta1.MsgUnjail",
    "/cosmos.slashing.v1beta1.MsgUpdateParams",
    "/cosmos.staking.v1beta1.MsgBeginRedelegate",
    "/cosmos.staking.v1beta1.MsgCancelUnbondingDelegation",
    "/cosmos.staking.v1beta1.MsgCreateValidator",
    "/cosmos.staking.v1beta1.MsgDelegate",
    "/cosmos.staking.v1beta1.MsgEditValidator",
    "/cosmos.staking.v1beta1.MsgRotateConsPubKey",
    "/cosmos.staking.v1beta1.MsgUndelegate",
    "/cosmos.staking.v1beta1.MsgUpdateParams",
    "/cosmos.upgrade.v1beta1.MsgCancelUpgrade",
    "/cosmos.upgrade.v1beta1.MsgSoftwareUpgrade",
    "/cosmos.vesting.v1beta1.MsgCreatePeriodicVestingAccount",
    "/cosmos.vesting.v1beta1.MsgCreatePermanentLockedAccount",
    "/cosmos.vesting.v1beta1.MsgCreateVestingAccount",
    "/cosmwasm.wasm.v1.MsgAddCircuitUploadParamsAddresses",
    "/cosmwasm.wasm.v1.MsgAddCodeUploadParamsAddresses",
    "/cosmwasm.wasm.v1.MsgClearAdmin",
    "/cosmwasm.wasm.v1.MsgExecuteContract",
    "/cosmwasm.wasm.v1.MsgInstantiateContract",
    "/cosmwasm.wasm.v1.MsgInstantiateContract2",
    "/cosmwasm.wasm.v1.MsgMigrateContract",
    "/cosmwasm.wasm.v1.MsgPinCodes",
    "/cosmwasm.wasm.v1.MsgRemoveCircuitUploadParamsAddresses",
    "/cosmwasm.wasm.v1.MsgRemoveCodeUploadParamsAddresses",
    "/cosmwasm.wasm.v1.MsgStoreAndInstantiateContract",
    "/cosmwasm.wasm.v1.MsgStoreAndMigrateContract",
    "/cosmwasm.wasm.v1.MsgStoreCircuit",
    "/cosmwasm.wasm.v1.MsgStoreCode",
    "/cosmwasm.wasm.v1.MsgStoreFullCircuit",
    "/cosmwasm.wasm.v1.MsgStoreVkParam",
    "/cosmwasm.wasm.v1.MsgSudoContract",
    "/cosmwasm.wasm.v1.MsgUnpinCircuits",
    "/cosmwasm.wasm.v1.MsgUnpinCodes",
    "/cosmwasm.wasm.v1.MsgUpdateAdmin",
    "/cosmwasm.wasm.v1.MsgUpdateContractLabel",
    "/cosmwasm.wasm.v1.MsgUpdateInstantiateConfig",
    "/cosmwasm.wasm.v1.MsgUpdateParams",
    "/gaia.globalfee.v1beta1.MsgUpdateParams",
    "/ibc.applications.interchain_accounts.controller.v1.MsgRegisterInterchainAccount",
    "/ibc.applications.interchain_accounts.controller.v1.MsgSendTx",
    "/ibc.applications.interchain_accounts.controller.v1.MsgUpdateParams",
    "/ibc.applications.interchain_accounts.host.v1.MsgModuleQuerySafe",
    "/ibc.applications.interchain_accounts.host.v1.MsgUpdateParams",
    "/ibc.applications.transfer.v1.MsgTransfer",
    "/ibc.applications.transfer.v1.MsgUpdateParams",
    "/ibc.core.channel.v1.MsgAcknowledgement",
    "/ibc.core.channel.v1.MsgChannelCloseConfirm",
    "/ibc.core.channel.v1.MsgChannelCloseInit",
    "/ibc.core.channel.v1.MsgChannelOpenAck",
    "/ibc.core.channel.v1.MsgChannelOpenConfirm",
    "/ibc.core.channel.v1.MsgChannelOpenInit",
    "/ibc.core.channel.v1.MsgChannelOpenTry",
    "/ibc.core.channel.v1.MsgRecvPacket",
    "/ibc.core.channel.v1.MsgTimeout",
    "/ibc.core.channel.v1.MsgTimeoutOnClose",
    "/ibc.core.channel.v2.MsgAcknowledgement",
    "/ibc.core.channel.v2.MsgRecvPacket",
    "/ibc.core.channel.v2.MsgSendPacket",
    "/ibc.core.channel.v2.MsgTimeout",
    "/ibc.core.client.v1.MsgCreateClient",
    "/ibc.core.client.v1.MsgDeleteClientCreator",
    "/ibc.core.client.v1.MsgIBCSoftwareUpgrade",
    "/ibc.core.client.v1.MsgRecoverClient",
    "/ibc.core.client.v1.MsgUpdateClient",
    "/ibc.core.client.v1.MsgUpdateClientParams",
    "/ibc.core.client.v1.MsgUpgradeClient",
    "/ibc.core.client.v2.MsgRegisterCounterparty",
    "/ibc.core.client.v2.MsgUpdateClientConfig",
    "/ibc.core.connection.v1.MsgConnectionOpenAck",
    "/ibc.core.connection.v1.MsgConnectionOpenConfirm",
    "/ibc.core.connection.v1.MsgConnectionOpenInit",
    "/ibc.core.connection.v1.MsgConnectionOpenTry",
    "/ibc.core.connection.v1.MsgUpdateConnectionParams",
    "/ibc.lightclients.wasm.v1.MsgMigrateContract",
    "/ibc.lightclients.wasm.v1.MsgRemoveChecksum",
    "/ibc.lightclients.wasm.v1.MsgStoreCode",
    "/osmosis.tokenfactory.v1beta1.MsgBurn",
    "/osmosis.tokenfactory.v1beta1.MsgChangeAdmin",
    "/osmosis.tokenfactory.v1beta1.MsgCreateDenom",
    "/osmosis.tokenfactory.v1beta1.MsgForceTransfer",
    "/osmosis.tokenfactory.v1beta1.MsgMint",
    "/osmosis.tokenfactory.v1beta1.MsgSetDenomMetadata",
    "/osmosis.tokenfactory.v1beta1.MsgUpdateParams",
    "/terp.drip.v1.MsgDistributeTokens",
    "/terp.drip.v1.MsgUpdateParams",
    "/terp.feeshare.v1.MsgCancelFeeShare",
    "/terp.feeshare.v1.MsgRegisterFeeShare",
    "/terp.feeshare.v1.MsgUpdateFeeShare",
    "/terp.feeshare.v1.MsgUpdateParams",
    "/terp.hashmerchant.v1.MsgRefillEscrow",
    "/terp.hashmerchant.v1.MsgRegisterChain",
    "/terp.hashmerchant.v1.MsgRegisterContract",
    "/terp.hashmerchant.v1.MsgUpdateParams",
    "/terp.smartaccount.v1beta1.MsgAddAuthenticator",
    "/terp.smartaccount.v1beta1.MsgRemoveAuthenticator",
    "/terp.smartaccount.v1beta1.MsgSetActiveState",
];

/// Owned copy of [`WALLET_TYPE_URLS`], in the same order.
pub fn wallet_type_urls() -> Vec<String> {
    WALLET_TYPE_URLS.iter().map(|url| (*url).to_string()).collect()
}

/// What a self-relayer sends on each chain while opening a client and
/// carrying packets. The same list is granted on every chain in the path.
/// It is not the wallet catalog.
pub const RELAY_TYPE_URLS: &[&str] = &[
    "/ibc.core.client.v1.MsgCreateClient",
    "/ibc.core.client.v1.MsgUpdateClient",
    "/ibc.core.connection.v1.MsgConnectionOpenInit",
    "/ibc.core.connection.v1.MsgConnectionOpenTry",
    "/ibc.core.connection.v1.MsgConnectionOpenAck",
    "/ibc.core.connection.v1.MsgConnectionOpenConfirm",
    "/ibc.core.channel.v1.MsgChannelOpenInit",
    "/ibc.core.channel.v1.MsgChannelOpenTry",
    "/ibc.core.channel.v1.MsgChannelOpenAck",
    "/ibc.core.channel.v1.MsgChannelOpenConfirm",
    "/ibc.core.channel.v1.MsgRecvPacket",
    "/ibc.core.channel.v1.MsgAcknowledgement",
    "/ibc.core.channel.v1.MsgTimeout",
    "/ibc.core.channel.v1.MsgTimeoutOnClose",
    "/ibc.applications.transfer.v1.MsgTransfer",
];

/// One authz and feegrant plan per chain. Nothing is broadcast.
pub fn relay_grants(chain_ids: &[&str]) -> Vec<(String, Vec<String>)> {
    let urls: Vec<String> = RELAY_TYPE_URLS.iter().map(|url| (*url).to_string()).collect();
    chain_ids
        .iter()
        .map(|chain_id| ((*chain_id).to_string(), urls.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wallet_catalog_is_unique_and_covers_terp() {
        let mut sorted = WALLET_TYPE_URLS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), WALLET_TYPE_URLS.len());
        for url in [
            "/cosmwasm.wasm.v1.MsgStoreCode",
            "/cosmwasm.wasm.v1.MsgExecuteContract",
            "/cosmwasm.wasm.v1.MsgInstantiateContract",
            "/cosmos.bank.v1beta1.MsgSend",
            "/ibc.applications.transfer.v1.MsgTransfer",
            "/ibc.core.channel.v1.MsgRecvPacket",
            "/ibc.core.channel.v2.MsgSendPacket",
            "/osmosis.tokenfactory.v1beta1.MsgCreateDenom",
            "/terp.feeshare.v1.MsgRegisterFeeShare",
            "/terp.drip.v1.MsgDistributeTokens",
            "/terp.smartaccount.v1beta1.MsgAddAuthenticator",
            "/terp.hashmerchant.v1.MsgRegisterContract",
            "/gaia.globalfee.v1beta1.MsgUpdateParams",
        ] {
            assert!(WALLET_TYPE_URLS.contains(&url), "{url}");
        }
        assert!(RELAY_TYPE_URLS
            .iter()
            .all(|url| WALLET_TYPE_URLS.contains(url)));
        assert!(WALLET_TYPE_URLS.iter().all(|url| !url.contains("thorchain")));
        assert!(WALLET_TYPE_URLS
            .iter()
            .all(|url| !url.contains("applications.fee")));
    }

    #[test]
    fn a_relay_grant_is_prepared_on_every_chain_before_any_send() {
        let grants = relay_grants(&["240u-1", "osmosis-1"]);
        assert_eq!(grants.len(), 2);
        assert_eq!(grants[0].0, "240u-1");
        assert_eq!(grants[1].0, "osmosis-1");
        assert_eq!(grants[0].1, grants[1].1);
        assert!(grants[0].1.iter().any(|url| url.ends_with("MsgCreateClient")));
        assert!(grants[0].1.iter().any(|url| url.ends_with("MsgRecvPacket")));
        assert!(grants[0].1.iter().any(|url| url.ends_with("MsgAcknowledgement")));
        assert!(grants[0]
            .1
            .iter()
            .all(|url| !url.ends_with("MsgGrant") && !url.ends_with("MsgGrantAllowance")));
    }
}
