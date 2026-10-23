use cosmrs::proto::cosmos::base::tendermint::v1beta1::{
    service_client::ServiceClient, GetNodeInfoRequest,
};
use cw_orch_core::{environment::ChainInfoOwned, log::connectivity_target};
use http::Uri;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use super::error::DaemonError;

/// Send and receive cap for tx simulation, broadcast, and tx queries.
/// A store of `dao_calendar.wasm` is larger than tonic's 4MB default.
pub const GRPC_MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// A helper for constructing a gRPC channel
pub struct GrpcChannel {}

pub(crate) fn tx_service(
    channel: Channel,
) -> crate::cosmos_modules::tx::service_client::ServiceClient<Channel> {
    crate::cosmos_modules::tx::service_client::ServiceClient::new(channel)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES)
}

impl GrpcChannel {
    /// Connect to any of the provided gRPC endpoints
    pub async fn connect(grpc: &[String], chain_id: &str) -> Result<Channel, DaemonError> {
        if grpc.is_empty() {
            return Err(DaemonError::GRPCListIsEmpty);
        }

        let mut successful_connections = vec![];

        for address in grpc.iter() {
            log::debug!(target: &connectivity_target(), "Trying to connect to endpoint: {}", address);

            let uri = Uri::from_maybe_shared(address.clone()).expect("Invalid URI");

            let mut endpoint = Endpoint::from(uri.clone());
            // Plain http:// (LAN sentries, local nodes) must not force TLS.
            if uri.scheme_str() == Some("https") {
                endpoint = endpoint
                    .tls_config(
                        ClientTlsConfig::new()
                            .with_enabled_roots()
                            .assume_http2(true),
                    )
                    .unwrap();
            }
            let maybe_channel = endpoint.connect().await;

            if maybe_channel.is_err() {
                log::warn!(
                    "Cannot connect to gRPC endpoint: {}, {:?}",
                    address,
                    maybe_channel.unwrap_err()
                );
                continue;
            };
            let channel = maybe_channel.unwrap();

            let mut client = ServiceClient::new(channel.clone());

            // Verify that node is the expected network
            let node_info = client
                .get_node_info(GetNodeInfoRequest {})
                .await?
                .into_inner();

            if node_info.default_node_info.as_ref().unwrap().network != chain_id {
                log::error!(
                    "Network mismatch: connection:{} != config:{}",
                    node_info.default_node_info.as_ref().unwrap().network,
                    chain_id
                );
                log::error!(
                    "default:{:#?} != ::: uri: {:#?}",
                    node_info.default_node_info,
                    uri
                );
                continue;
            }

            // add endpoint to succesful connections
            successful_connections.push(channel);
        }

        // we could not get any succesful connections
        if successful_connections.is_empty() {
            return Err(DaemonError::CannotConnectGRPC);
        }

        Ok(successful_connections.pop().unwrap())
    }

    /// Create a gRPC channel from the chain info
    pub async fn from_chain_info(chain_info: &ChainInfoOwned) -> Result<Channel, DaemonError> {
        GrpcChannel::connect(&chain_info.grpc_urls, &chain_info.chain_id).await
    }
}

#[cfg(test)]
mod tests {
    /*
        This test asserts breaking issues around the GRPC connection
    */

    use crate::DaemonAsync;
    use speculoos::prelude::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn no_connection() {
        let mut chain = cw_orch_daemon::networks::LOCAL_JUNO;
        let grpcs = &["https://127.0.0.1:99999"];
        chain.grpc_urls = grpcs;

        let build_res = DaemonAsync::builder(chain)
            .deployment_id("v0.1.0")
            .build_sender(())
            .await;

        asserting!("there is no GRPC connection")
            .that(&build_res.err().unwrap().to_string())
            .is_equal_to(String::from(
                "Can not connect to any grpc endpoint that was provided.",
            ))
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn network_grpcs_list_is_empty() {
        let mut chain = cw_orch_daemon::networks::LOCAL_JUNO;
        let grpcs = &[];
        chain.grpc_urls = grpcs;

        let build_res = DaemonAsync::builder(chain)
            .is_test(true)
            .deployment_id("v0.1.0")
            .build_sender(())
            .await;

        asserting!("GRPC list is empty")
            .that(&build_res.err().unwrap().to_string())
            .is_equal_to(String::from("The list of grpc endpoints is empty"))
    }
}
