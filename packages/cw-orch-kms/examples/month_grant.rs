//! One cold signature: replace the short factory grant with a 30-day grant.
//! The runtime key may create one series collection a day for a month.
use cw_orch_core::environment::{ChainInfoOwned, ChainKind, NetworkInfoOwned};
use cw_orch_daemon::DaemonBuilder;
use cw_orch_kms::{grant_to, ApprovalSession, ScopedCall, SigningRequest};

fn main() {
    let granter = "terp1fxccvvhhy43tvet2ah7jqwq4cwl9k3dxmww052";
    let operator = "terp130aem4enrw9nnjps9ch8v2v2msl7ukayxcgr5r";
    let factory = "terp1wg5z9rcwpw5kvrl4g78ees2l9ejptrhrx4t2k56nq6t27uly87zssujm80";
    let calls = 31u64;
    let ttl = 30 * 86_400;
    let info = ChainInfoOwned {
        chain_id: "morocco-1".into(),
        gas_denom: "uthiol".into(),
        gas_price: 0.05,
        grpc_urls: vec!["http://127.0.0.1:19090".into()],
        rpc_urls: vec!["http://127.0.0.1:26658".into()],
        lcd_url: None,
        fcd_url: None,
        network_info: NetworkInfoOwned {
            chain_name: "terp".into(),
            pub_address_prefix: "terp".into(),
            coin_type: 118,
        },
        kind: ChainKind::Mainnet,
    };
    let mut builder = DaemonBuilder::new(info);
    builder.load_network(false);
    builder.grpc_url("http://127.0.0.1:19090");
    let mut session = ApprovalSession::open(granter).allow_execute(ScopedCall {
        address: factory.into(),
        keys: vec!["create_series_collection".into()],
        calls: calls + 1,
        funds: vec![],
    }).expect("execute grant");
    session.retain = true;
    session.operator_grant = true;
    session.ttl_secs = ttl;
    session.allowance_limit = cw_orch_kms::planned_spend_limit(calls + 1);
    let reqs = vec![SigningRequest::new("session-key").body(format!(
        "revoke the 24-hour 20-call factory grant and replace it: {operator} may create_series_collection on {factory} {calls} times over 30 days. Fees are paid by {granter}."
    ))];
    grant_to(&builder, session, operator, reqs).expect("grant");
    println!("operator {operator} may create_series_collection {calls} times over 30 days");
}
