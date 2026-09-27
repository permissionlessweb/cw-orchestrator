//! Protobuf for `/terp.smartaccount.v1beta1.TxExtension` and `MsgAddAuthenticator`.
//! Field numbers match `proto/terp/smartaccount/v1beta1/tx.proto`.

use cosmrs::Any;

pub fn extension_any(authenticator_id: u64) -> Any {
    Any {
        type_url: "/terp.smartaccount.v1beta1.TxExtension".into(),
        value: tx_extension(authenticator_id),
    }
}

pub fn add_authenticator_any(sender: &str, contract: &str) -> Any {
    let init = format!(r#"{{"contract":"{contract}"}}"#);
    Any {
        type_url: "/terp.smartaccount.v1beta1.MsgAddAuthenticator".into(),
        value: msg_add_authenticator(sender, "CosmwasmAuthenticatorV1", init.as_bytes()),
    }
}

fn tx_extension(authenticator_id: u64) -> Vec<u8> {
    let packed = varint(authenticator_id);
    let mut out = vec![0x0a];
    out.extend(varint(packed.len() as u64));
    out.extend(packed);
    out
}

fn msg_add_authenticator(sender: &str, authenticator_type: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(length_delimited(1, sender.as_bytes()));
    out.extend(length_delimited(2, authenticator_type.as_bytes()));
    out.extend(length_delimited(3, data));
    out
}

fn length_delimited(field: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint(((field as u64) << 3) | 2);
    out.extend(varint(bytes.len() as u64));
    out.extend(bytes);
    out
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_for_authenticator_one_is_packed_varint() {
        assert_eq!(tx_extension(1), vec![0x0a, 0x01, 0x01]);
        let any = extension_any(7);
        assert_eq!(any.type_url, "/terp.smartaccount.v1beta1.TxExtension");
        assert_eq!(any.value, vec![0x0a, 0x01, 0x07]);
    }
}
