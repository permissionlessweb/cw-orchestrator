//! `penumbra.custody.v1.CustodyService` backed by Zigner. Each `Authorize`
//! call runs the policy, puts the plan on the run's page ([`page::Approvals`])
//! and blocks until the phone's signatures verify (or the page refuses / times
//! out).
//! Validator definition/vote signing is not offered.

use super::{page, policy::Policy, PinnedAccount};
use penumbra_sdk_custody::AuthorizeRequest;
use penumbra_sdk_proto::custody::v1::{self as pb, custody_service_server::CustodyService};
use penumbra_sdk_transaction::{AuthorizationData, TransactionPlan};
use std::{net::SocketAddr, time::Duration};
use std::sync::Arc;
use tonic012 as tonic;
use tonic::{Request, Response, Status};

pub struct ZignerCustody {
    pub account: PinnedAccount,
    pub policy: Policy,
    /// The page the plans appear on (one page per run).
    pub approvals: Arc<page::Approvals>,
    pub timeout: Duration,
    pub asset_names: Vec<String>,
}

impl ZignerCustody {
    pub fn new(account: PinnedAccount, policy: Policy, approvals: Arc<page::Approvals>, timeout: Duration) -> Self {
        Self { account, policy, approvals, timeout, asset_names: vec![] }
    }

    /// Library entry point (no gRPC): policy, page, verified AuthorizationData.
    pub async fn authorize_plan(&self, plan: &TransactionPlan) -> anyhow::Result<AuthorizationData> {
        self.policy.check(plan, &self.account.fvk)?;
        self.approvals.approve(plan, &self.account.fvk, self.asset_names.clone(), self.timeout).await
    }
}

#[tonic::async_trait]
impl CustodyService for ZignerCustody {
    async fn authorize(&self, request: Request<pb::AuthorizeRequest>) -> Result<Response<pb::AuthorizeResponse>, Status> {
        let req: AuthorizeRequest = request.into_inner().try_into().map_err(|e: anyhow::Error| Status::invalid_argument(e.to_string()))?;
        let data = self.authorize_plan(&req.plan).await.map_err(|e| Status::permission_denied(format!("{e:#}")))?;
        Ok(Response::new(pb::AuthorizeResponse { data: Some(data.into()) }))
    }

    async fn authorize_validator_definition(
        &self,
        _r: Request<pb::AuthorizeValidatorDefinitionRequest>,
    ) -> Result<Response<pb::AuthorizeValidatorDefinitionResponse>, Status> {
        Err(Status::unimplemented("zigner custody does not sign validator definitions"))
    }

    async fn authorize_validator_vote(
        &self,
        _r: Request<pb::AuthorizeValidatorVoteRequest>,
    ) -> Result<Response<pb::AuthorizeValidatorVoteResponse>, Status> {
        Err(Status::unimplemented("zigner custody does not sign validator votes"))
    }

    async fn export_full_viewing_key(
        &self,
        _r: Request<pb::ExportFullViewingKeyRequest>,
    ) -> Result<Response<pb::ExportFullViewingKeyResponse>, Status> {
        // The FVK is session-scoped confidential data: never hand it out over gRPC.
        Err(Status::permission_denied("zigner custody does not export the full viewing key"))
    }

    async fn confirm_address(&self, request: Request<pb::ConfirmAddressRequest>) -> Result<Response<pb::ConfirmAddressResponse>, Status> {
        let ix = request
            .into_inner()
            .address_index
            .ok_or_else(|| Status::invalid_argument("missing address index"))?
            .try_into()
            .map_err(|e: anyhow::Error| Status::invalid_argument(e.to_string()))?;
        let (address, _) = self.account.fvk.payment_address(ix);
        Ok(Response::new(pb::ConfirmAddressResponse { address: Some(address.into()) }))
    }
}

/// Serve the custody service on loopback.
pub async fn serve(custody: ZignerCustody, grpc_addr: SocketAddr) -> anyhow::Result<()> {
    anyhow::ensure!(grpc_addr.ip().is_loopback(), "custody gRPC binds loopback only");
    anyhow::ensure!(grpc_addr.port() != page::RESERVED_PORT, "port {} is reserved", page::RESERVED_PORT);
    tonic::transport::Server::builder()
        .add_service(pb::custody_service_server::CustodyServiceServer::new(custody))
        .serve(grpc_addr)
        .await?;
    Ok(())
}

/// Serve on an already-bound loopback listener (lets callers pick port 0).
pub async fn serve_listener(custody: ZignerCustody, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let a = listener.local_addr()?;
    anyhow::ensure!(a.ip().is_loopback(), "custody gRPC binds loopback only");
    anyhow::ensure!(a.port() != page::RESERVED_PORT, "port {} is reserved", page::RESERVED_PORT);
    tonic::transport::Server::builder()
        .add_service(pb::custody_service_server::CustodyServiceServer::new(custody))
        .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
        .await?;
    Ok(())
}
