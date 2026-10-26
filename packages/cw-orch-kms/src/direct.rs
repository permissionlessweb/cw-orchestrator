//! `MsgExec{grantee, [MsgExecuteContract{sender: granter}]}` builder.
//!
//! An operator that holds a retained grant from another granter relays it
//! from a short session key: the session key sends
//! `MsgExec(session){MsgExec(operator){MsgExecuteContract(granter)}}`. The
//! inner `MsgExec` is [`exec_contract_as`]. The cold key never signs these
//! messages; it signs only the session grant.

use cosmrs::proto::traits::Message;

/// One message with its legacy-amino JSON (what the cold key reads and signs)
/// and its protobuf `Any` (what goes in the body).
#[derive(Clone, Debug)]
pub struct AminoMsg {
    pub amino: String,
    pub any: cosmrs::Any,
}

/// Canonical JSON as the chain rebuilds it for SIGN_MODE_LEGACY_AMINO_JSON:
/// object keys sorted, no whitespace, Go `encoding/json` escaping (`<`, `>`,
/// `&`, U+2028, U+2029 as `\u00XX`).
pub fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_go_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_go_string(key, out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

fn write_go_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `MsgExec{grantee, [MsgExecuteContract{sender: granter, contract, msg, funds}]}`.
/// The contract message bytes are the canonical JSON, so the bytes in the body
/// and the bytes the chain re-renders for the signature are the same.
pub fn exec_contract_as(
    grantee: &str,
    granter: &str,
    contract: &str,
    msg: &serde_json::Value,
    funds: &[(String, u128)],
) -> Result<AminoMsg, String> {
    use cosmos_sdk_proto::cosmos::authz::v1beta1::MsgExec;
    use cosmos_sdk_proto::cosmos::base::v1beta1::Coin as ProtoCoin;
    use cosmos_sdk_proto::cosmwasm::wasm::v1::MsgExecuteContract;
    if !msg.is_object() {
        return Err("direct tx refused: the contract message is not a JSON object".into());
    }
    let msg_json = canonical_json(msg);
    let mut funds = funds.to_vec();
    funds.sort_by(|a, b| a.0.cmp(&b.0));
    let inner = MsgExecuteContract {
        sender: granter.to_string(),
        contract: contract.to_string(),
        msg: msg_json.clone().into_bytes(),
        funds: funds
            .iter()
            .map(|(denom, amount)| ProtoCoin { denom: denom.clone(), amount: amount.to_string() })
            .collect(),
    };
    let exec = MsgExec {
        grantee: grantee.to_string(),
        msgs: vec![cosmos_sdk_proto::Any {
            type_url: "/cosmwasm.wasm.v1.MsgExecuteContract".into(),
            value: inner.encode_to_vec(),
        }],
    };
    let funds_amino: Vec<String> = funds
        .iter()
        .map(|(denom, amount)| format!("{{\"amount\":\"{amount}\",\"denom\":{}}}", quote(denom)))
        .collect();
    let amino = format!(
        "{{\"type\":\"cosmos-sdk/MsgExec\",\"value\":{{\"grantee\":{},\"msgs\":[{{\"type\":\"wasm/MsgExecuteContract\",\"value\":{{\"contract\":{},\"funds\":[{}],\"msg\":{},\"sender\":{}}}}}]}}}}",
        quote(grantee),
        quote(contract),
        funds_amino.join(","),
        msg_json,
        quote(granter),
    );
    Ok(AminoMsg {
        amino,
        any: cosmrs::Any { type_url: "/cosmos.authz.v1beta1.MsgExec".into(), value: exec.encode_to_vec() },
    })
}

fn quote(s: &str) -> String {
    let mut out = String::new();
    write_go_string(s, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmos_sdk_proto::cosmos::authz::v1beta1::MsgExec;
    use cosmos_sdk_proto::cosmwasm::wasm::v1::MsgExecuteContract;

    const OP: &str = "terp1nkd7zql5hm5tds7rp95yu7ty47a4qzcxvepjzd";
    const GR: &str = "terp1denpf5rdle2rwgdl8n7n22n6d3cwzt844u2qtz";
    const C: &str = "terp1lcethwm5x96dnn2ju7cx834pm3u025d639ma3lyt3r8mgpqlf3aqqurp7x";

    #[test]
    fn canonical_json_sorts_keys_and_uses_go_escaping() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":{"z":1,"a":[true,null]},"a":"<svg>&\u2028\n\"x\""}"#).unwrap();
        assert_eq!(canonical_json(&v), r#"{"a":"\u003csvg\u003e\u0026\u2028\n\"x\"","b":{"a":[true,null],"z":1}}"#);
    }

    #[test]
    fn exec_wraps_the_granter_call_and_the_bytes_match_the_amino() {
        let msg: serde_json::Value = serde_json::from_str(r#"{"set_series":{"series":"s","config":null}}"#).unwrap();
        let m = exec_contract_as(OP, GR, C, &msg, &[("uthiol".into(), 5)]).unwrap();
        assert_eq!(m.any.type_url, "/cosmos.authz.v1beta1.MsgExec");
        let exec = MsgExec::decode(m.any.value.as_slice()).unwrap();
        assert_eq!(exec.grantee, OP);
        assert_eq!(exec.msgs.len(), 1);
        let inner = MsgExecuteContract::decode(exec.msgs[0].value.as_slice()).unwrap();
        assert_eq!(inner.sender, GR);
        assert_eq!(inner.contract, C);
        let body = String::from_utf8(inner.msg).unwrap();
        assert_eq!(body, r#"{"set_series":{"config":null,"series":"s"}}"#);
        assert!(m.amino.contains(&format!("\"msg\":{body}")));
        assert!(m.amino.starts_with("{\"type\":\"cosmos-sdk/MsgExec\",\"value\":{\"grantee\":"));
        assert!(m.amino.contains("\"funds\":[{\"amount\":\"5\",\"denom\":\"uthiol\"}]"));
        let parsed: serde_json::Value = serde_json::from_str(&m.amino).unwrap();
        assert_eq!(canonical_json(&parsed), m.amino, "amino is already canonical");
    }

    #[test]
    fn exec_without_funds_keeps_an_empty_funds_list() {
        let msg = serde_json::json!({"create_svg_collection": {"label": "x"}});
        let m = exec_contract_as(OP, GR, C, &msg, &[]).unwrap();
        assert!(m.amino.contains("\"funds\":[]"));
        assert!(exec_contract_as(OP, GR, C, &serde_json::json!("x"), &[]).is_err());
    }
}
