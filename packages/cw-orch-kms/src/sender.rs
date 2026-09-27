//! Account pubkey identifies the smart account. Signature bytes are the
//! terp-frost quorum over the SIGN_MODE_DIRECT sign doc.

use std::sync::Arc;

use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest};
use cosmrs::proto::cosmos::tx::v1beta1::{BroadcastMode, BroadcastTxRequest, GetTxRequest};
use cosmrs::proto::traits::Message;
use cosmrs::tendermint::chain::Id;
use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;
use cosmrs::tx::{Body, ModeInfo, Raw, SignDoc, SignMode, SignerInfo, SignerPublicKey};
use cosmrs::AccountId;
use cosmrs::Any;
use cw_orch_core::environment::ChainInfoOwned;
use cw_orch_daemon::queriers::Node;
use cw_orch_daemon::senders::builder::SenderBuilder;
use cw_orch_daemon::senders::query::QuerySender;
use cw_orch_daemon::senders::sign::Signer;
use cw_orch_daemon::senders::tx::TxSender;
use cw_orch_daemon::{CosmTxResponse, DaemonError, GrpcChannel, TxBuilder, Wallet};
use tonic::transport::Channel;

use crate::session::FrostSession;
use crate::tx_extension;

const SUBMISSION_GAS_BUFFER: f64 = 1.4;

#[derive(Clone)]
pub struct FrostKmsOptions {
    pub account_id: AccountId,
    pub public_key: SignerPublicKey,
    pub authenticator_id: u64,
    pub session: FrostSession,
}

impl FrostKmsOptions {
    pub fn from_wallet(
        wallet: &Wallet,
        authenticator_id: u64,
        session: FrostSession,
    ) -> Result<Self, DaemonError> {
        let public_key = wallet.public_key().ok_or_else(|| {
            DaemonError::StdErr(format!(
                "frost kms account {} has no secp256k1 public key",
                wallet.address()
            ))
        })?;
        Ok(Self {
            account_id: Signer::account_id(wallet),
            public_key,
            authenticator_id,
            session,
        })
    }
}

#[derive(Clone)]
pub struct FrostKmsSender {
    account_id: AccountId,
    public_key: SignerPublicKey,
    authenticator_id: u64,
    session: FrostSession,
    chain_info: Arc<ChainInfoOwned>,
    grpc_channel: Channel,
}

impl SenderBuilder for FrostKmsOptions {
    type Error = DaemonError;
    type Sender = FrostKmsSender;

    async fn build(&self, chain_info: &Arc<ChainInfoOwned>) -> Result<Self::Sender, Self::Error> {
        let grpc_channel = GrpcChannel::from_chain_info(chain_info.as_ref()).await?;
        Ok(FrostKmsSender {
            account_id: self.account_id.clone(),
            public_key: self.public_key.clone(),
            authenticator_id: self.authenticator_id,
            session: self.session.clone(),
            chain_info: chain_info.clone(),
            grpc_channel,
        })
    }
}

impl QuerySender for FrostKmsSender {
    type Error = DaemonError;
    type Options = FrostKmsOptions;

    fn channel(&self) -> Channel {
        self.grpc_channel.clone()
    }
}

impl FrostKmsSender {
    pub fn group_vk(&self) -> &str {
        self.session.group_vk()
    }

    async fn account(&self) -> Result<BaseAccount, DaemonError> {
        let mut client =
            cosmrs::proto::cosmos::auth::v1beta1::query_client::QueryClient::new(self.channel());
        let resp = client
            .account(QueryAccountRequest {
                address: self.account_id.to_string(),
            })
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms account query failed for {}: {err}",
                    self.account_id
                ))
            })?
            .into_inner();
        let any = resp.account.ok_or_else(|| {
            DaemonError::StdErr(format!(
                "frost kms account {} is not on chain",
                self.account_id
            ))
        })?;
        BaseAccount::decode(any.value.as_slice()).map_err(|err| {
            DaemonError::StdErr(format!(
                "frost kms account {} is not a BaseAccount: {err}",
                self.account_id
            ))
        })
    }

    fn raw_tx(
        &self,
        body: &Body,
        sequence: u64,
        account_number: u64,
        gas_limit: u64,
        fee_amount: u128,
        signature: Vec<u8>,
    ) -> Result<(Raw, Vec<u8>), DaemonError> {
        let fee = TxBuilder::build_fee(
            fee_amount,
            &self.chain_info.gas_denom,
            gas_limit,
            None,
        )?;
        let auth_info = SignerInfo {
            public_key: Some(self.public_key.clone()),
            mode_info: ModeInfo::single(SignMode::Direct),
            sequence,
        }
        .auth_info(fee);
        let sign_doc = SignDoc::new(
            body,
            &auth_info,
            &Id::try_from(self.chain_info.chain_id.clone())?,
            account_number,
        )?;
        let sign_doc_bytes = sign_doc.clone().into_bytes()?;
        Ok((
            Raw::from(TxRaw {
                body_bytes: sign_doc.body_bytes,
                auth_info_bytes: sign_doc.auth_info_bytes,
                signatures: vec![signature],
            }),
            sign_doc_bytes,
        ))
    }
}

impl TxSender for FrostKmsSender {
    fn account_id(&self) -> AccountId {
        self.account_id.clone()
    }

    async fn commit_tx_any(
        &self,
        msgs: Vec<Any>,
        memo: Option<&str>,
    ) -> Result<CosmTxResponse, DaemonError> {
        let node = Node::new_async(self.channel());
        let timeout_height = node._block_height().await? + 10;
        let mut body = Body::new(msgs, memo.unwrap_or("frost kms"), timeout_height as u32);
        body.non_critical_extension_options
            .push(tx_extension::extension_any(self.authenticator_id));

        let account = self.account().await?;
        let (simulated, _) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            0,
            0,
            Vec::new(),
        )?;
        let gas_used = simulate_gas_used(self.channel(), simulated.to_bytes()?)
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms simulate failed for {} authenticator {}: {err}",
                    self.account_id, self.authenticator_id
                ))
            })?;
        let gas_limit = ((gas_used as f64) * SUBMISSION_GAS_BUFFER).ceil() as u64;
        let fee_amount = ((gas_limit as f64) * self.chain_info.gas_price).ceil() as u128;
        let (_, sign_doc_bytes) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            gas_limit,
            fee_amount,
            Vec::new(),
        )?;
        let signature = self
            .session
            .sign(&sign_doc_bytes)
            .map_err(DaemonError::StdErr)?;
        let (raw, _) = self.raw_tx(
            &body,
            account.sequence,
            account.account_number,
            gas_limit,
            fee_amount,
            signature.to_vec(),
        )?;
        let broadcast = broadcast_lite(self.channel(), raw.to_bytes()?)
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms broadcast failed for {}: {err}",
                    self.account_id
                ))
            })?;
        if broadcast.code != 0 {
            return Err(DaemonError::TxFailed {
                code: broadcast.code as usize,
                reason: format!(
                    "frost kms broadcast code {} for {}: {}",
                    broadcast.code, self.account_id, broadcast.raw_log
                ),
            });
        }
        let found = find_tx_lite(self.channel(), &broadcast.txhash)
            .await
            .map_err(|err| {
                DaemonError::StdErr(format!(
                    "frost kms tx {} for {} not found: {err}",
                    broadcast.txhash, self.account_id
                ))
            })?;
        if found.code != 0 {
            return Err(DaemonError::TxFailed {
                code: found.code as usize,
                reason: format!(
                    "frost kms tx code {} for {}: {}",
                    found.code, self.account_id, found.raw_log
                ),
            });
        }
        Ok(CosmTxResponse {
            height: found.height as u64,
            txhash: found.txhash,
            codespace: found.codespace,
            code: found.code as usize,
            data: found.data,
            raw_log: found.raw_log,
            timestamp: chrono::Utc::now(),
            ..CosmTxResponse::default()
        })
    }

    async fn bank_send(
        &self,
        recipient: &cosmwasm_std::Addr,
        coins: &[cosmwasm_std::Coin],
    ) -> Result<CosmTxResponse, DaemonError> {
        let amount = cw_orch_daemon::parse_cw_coins(coins)?;
        let msg = cosmrs::bank::MsgSend {
            from_address: self.account_id.clone(),
            to_address: recipient.as_str().parse()?,
            amount,
        };
        self.commit_tx(vec![msg], Some("frost kms bank send")).await
    }
}

/// `SimulateResponse.result` carries event attributes. This chain emits
/// attribute values that are not UTF-8, and the generated decoder rejects the
/// whole response. Gas is field 1 and does not depend on those events.
#[derive(Clone, PartialEq, prost::Message)]
struct SimulateGasOnly {
    #[prost(message, optional, tag = "1")]
    gas_info: Option<cosmrs::proto::cosmos::base::abci::v1beta1::GasInfo>,
    #[prost(bytes = "vec", tag = "2")]
    _result: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct TxResponseLite {
    #[prost(int64, tag = "1")]
    height: i64,
    #[prost(string, tag = "2")]
    txhash: String,
    #[prost(string, tag = "3")]
    codespace: String,
    #[prost(uint32, tag = "4")]
    code: u32,
    #[prost(string, tag = "5")]
    data: String,
    #[prost(string, tag = "6")]
    raw_log: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct BroadcastLite {
    #[prost(message, optional, tag = "1")]
    tx_response: Option<TxResponseLite>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct GetTxLite {
    #[prost(bytes = "vec", tag = "1")]
    _tx: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    tx_response: Option<TxResponseLite>,
}

async fn broadcast_lite(channel: Channel, tx_bytes: Vec<u8>) -> Result<TxResponseLite, String> {
    use tonic::client::Grpc;
    use tonic::Request;
    use tonic_prost::ProstCodec;

    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| format!("broadcast channel not ready: {err}"))?;
    let path = http::uri::PathAndQuery::from_static("/cosmos.tx.v1beta1.Service/BroadcastTx");
    let response = grpc
        .unary(
            Request::new(BroadcastTxRequest {
                tx_bytes,
                mode: BroadcastMode::Sync.into(),
            }),
            path,
            ProstCodec::<BroadcastTxRequest, BroadcastLite>::default(),
        )
        .await
        .map_err(|err| format!("broadcast rpc status {err}"))?;
    response
        .into_inner()
        .tx_response
        .ok_or_else(|| "broadcast returned no tx response".to_string())
}

async fn find_tx_lite(channel: Channel, hash: &str) -> Result<TxResponseLite, String> {
    use tonic::client::Grpc;
    use tonic::Request;
    use tonic_prost::ProstCodec;

    let path = http::uri::PathAndQuery::from_static("/cosmos.tx.v1beta1.Service/GetTx");
    let mut wait = std::time::Duration::from_secs(1);
    let mut last = String::from("not queried");
    for _ in 0..12 {
        let mut grpc = Grpc::new(channel.clone());
        grpc.ready()
            .await
            .map_err(|err| format!("get_tx channel not ready: {err}"))?;
        match grpc
            .unary(
                Request::new(GetTxRequest {
                    hash: hash.to_string(),
                }),
                path.clone(),
                ProstCodec::<GetTxRequest, GetTxLite>::default(),
            )
            .await
        {
            Ok(response) => {
                if let Some(tx) = response.into_inner().tx_response {
                    return Ok(tx);
                }
                last = "get_tx response had no tx_response".into();
            }
            Err(err) => last = err.to_string(),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(std::time::Duration::from_secs(4));
    }
    Err(format!("tx {hash} after 12 tries: {last}"))
}

async fn simulate_gas_used(channel: Channel, tx_bytes: Vec<u8>) -> Result<u64, String> {
    use cosmrs::proto::cosmos::tx::v1beta1::SimulateRequest;
    use tonic::client::Grpc;
    use tonic::Request;
    use tonic_prost::ProstCodec;

    let mut grpc = Grpc::new(channel);
    grpc.ready()
        .await
        .map_err(|err| format!("simulate channel not ready: {err}"))?;
    let path = http::uri::PathAndQuery::from_static("/cosmos.tx.v1beta1.Service/Simulate");
    let response = grpc
        .unary(
            Request::new(SimulateRequest {
                tx: None,
                tx_bytes,
            }),
            path,
            ProstCodec::<SimulateRequest, SimulateGasOnly>::default(),
        )
        .await
        .map_err(|err| format!("simulate rpc status {err}"))?;
    let gas = response
        .into_inner()
        .gas_info
        .ok_or_else(|| "simulate response has no gas_info".to_string())?;
    Ok(gas.gas_used)
}
