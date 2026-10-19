//! Authz and feegrant bytes for one script session. Nothing is broadcast.

use cosmrs::proto::cosmos::authz::v1beta1::{GenericAuthorization, Grant, MsgGrant};
use cosmrs::proto::cosmos::feegrant::v1beta1::{BasicAllowance, MsgGrantAllowance};
use cosmrs::proto::traits::Message;
use cosmrs::Coin;
use prost::Name;

use crate::session::SessionGrant;

/// Encoded grants. Cosmos authz stores one type URL per `MsgGrant`, so a
/// run with several type URLs produces one grant each. The feegrant is one
/// `MsgGrantAllowance`.
pub struct SessionGrants {
    pub authz: Vec<Vec<u8>>,
    pub feegrant: Vec<u8>,
}

pub fn build_session_grants(
    granter: &str,
    grant: &SessionGrant,
    fee_denom: &str,
    fee_amount: u128,
) -> Result<SessionGrants, String> {
    if granter.is_empty() {
        return Err("grant refused: empty granter".into());
    }
    if grant.allowlist_type_urls().is_empty() {
        return Err(format!(
            "grant refused: session {} has no type urls",
            grant.session_id
        ));
    }
    let expiration = Some(cosmrs::proto::tendermint::google::protobuf::Timestamp {
        seconds: grant.expiration_unix as i64,
        nanos: 0,
    });
    let mut authz = Vec::new();
    for type_url in grant.allowlist_type_urls() {
        let authorization = GenericAuthorization { msg: type_url };
        let mut value = Vec::new();
        authorization
            .encode(&mut value)
            .map_err(|err| format!("grant authorization encode refused: {err}"))?;
        let msg = MsgGrant {
            granter: granter.to_string(),
            grantee: grant.grantee.clone(),
            grant: Some(Grant {
                authorization: Some(cosmrs::Any {
                    type_url: GenericAuthorization::type_url(),
                    value,
                }),
                expiration: expiration.clone(),
            }),
        };
        let mut bytes = Vec::new();
        msg.encode(&mut bytes)
            .map_err(|err| format!("grant encode refused: {err}"))?;
        authz.push(bytes);
    }
    let allowance = BasicAllowance {
        spend_limit: vec![Coin {
            denom: fee_denom
                .parse()
                .map_err(|err| format!("grant denom refused: {err}"))?,
            amount: fee_amount,
        }
        .into()],
        expiration: expiration.clone(),
    };
    let mut allowance_bytes = Vec::new();
    allowance
        .encode(&mut allowance_bytes)
        .map_err(|err| format!("feegrant allowance encode refused: {err}"))?;
    let fee = MsgGrantAllowance {
        granter: granter.to_string(),
        grantee: grant.grantee.clone(),
        allowance: Some(cosmrs::Any {
            type_url: BasicAllowance::type_url(),
            value: allowance_bytes,
        }),
    };
    let mut feegrant = Vec::new();
    fee.encode(&mut feegrant)
        .map_err(|err| format!("feegrant encode refused: {err}"))?;
    Ok(SessionGrants { authz, feegrant })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{MSG_EXECUTE, MSG_STORE_CODE};
    use crate::session::{ApprovalFactor, Clock, ScriptSession};
    use cosmrs::proto::traits::Message;
    use prost::Name;

    struct FixedClock;
    impl Clock for FixedClock {
        fn unix_secs(&self) -> u64 {
            5_000
        }
    }

    #[test]
    fn grants_name_the_grantee_the_type_urls_and_the_expiration() {
        let allow = crate::allowlist::RunAllowlist::default()
            .allow_type(MSG_STORE_CODE)
            .allow_type(MSG_EXECUTE);
        let session =
            ScriptSession::open(allow, ApprovalFactor::Zafu, 90, &FixedClock, "run-g").unwrap();
        let built = build_session_grants("terp1granter", session.grant(), "uterp", 25).unwrap();
        assert_eq!(built.authz.len(), 2);
        let mut urls = Vec::new();
        for bytes in &built.authz {
            let msg = MsgGrant::decode(bytes.as_slice()).unwrap();
            assert_eq!(msg.granter, "terp1granter");
            assert_eq!(msg.grantee, session.grantee());
            let inner = msg.grant.unwrap();
            assert_eq!(inner.expiration.unwrap().seconds, 5_090);
            let any = inner.authorization.unwrap();
            assert_eq!(any.type_url, GenericAuthorization::type_url());
            let auth = GenericAuthorization::decode(any.value.as_slice()).unwrap();
            urls.push(auth.msg);
        }
        urls.sort();
        assert_eq!(
            urls,
            vec![MSG_EXECUTE.to_string(), MSG_STORE_CODE.to_string()]
        );

        let fee = MsgGrantAllowance::decode(built.feegrant.as_slice()).unwrap();
        assert_eq!(fee.grantee, session.grantee());
        assert_eq!(fee.granter, "terp1granter");
        let any = fee.allowance.unwrap();
        let allowance = BasicAllowance::decode(any.value.as_slice()).unwrap();
        assert_eq!(allowance.expiration.unwrap().seconds, 5_090);
        assert_eq!(allowance.spend_limit[0].denom, "uterp");
        assert_eq!(allowance.spend_limit[0].amount, "25");
    }
}
