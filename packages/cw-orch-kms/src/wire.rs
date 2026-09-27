//! 65-byte Schnorr signature checked by `terp-frost` sudo Authenticate.
//!
//! osst `Signature::to_bytes` drops secp256k1 y parity. This encoding keeps the
//! 33-byte SEC1 point.

use osst::curve::{OsstCurve, OsstPoint, OsstScalar};
use osst::frost::Signature;
use osst::Secp256k1Curve;

pub type Point = <Secp256k1Curve as OsstCurve>::Point;
pub type Scalar = <Secp256k1Curve as OsstCurve>::Scalar;

pub const FROST_R_LEN: usize = 33;
pub const FROST_Z_LEN: usize = 32;
pub const FROST_SIG_LEN: usize = FROST_R_LEN + FROST_Z_LEN;

pub fn encode_group_vk(point: &Point) -> String {
    encode_hex(&point.compress_vec())
}

pub fn encode_signature(signature: &Signature<Point>) -> [u8; FROST_SIG_LEN] {
    let r = signature.r.compress_vec();
    assert!(
        r.len() == FROST_R_LEN,
        "secp256k1 compressed R must be {FROST_R_LEN} bytes, got {}",
        r.len()
    );
    let mut out = [0u8; FROST_SIG_LEN];
    out[..FROST_R_LEN].copy_from_slice(&r);
    out[FROST_R_LEN..].copy_from_slice(&signature.z.to_bytes());
    out
}

pub fn verify_group_signature(group_vk: &str, message: &[u8], signature: &[u8]) -> Result<(), String> {
    if message.is_empty() {
        return Err("empty sign doc".into());
    }
    if group_vk.len() != FROST_R_LEN * 2 || !group_vk.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(format!("group_vk is not a secp256k1 point: {group_vk}"));
    }
    let group_bytes = decode_hex(group_vk).ok_or_else(|| format!("group_vk is not a secp256k1 point: {group_vk}"))?;
    let group = Point::decompress_slice(&group_bytes)
        .ok_or_else(|| format!("group_vk is not a secp256k1 point: {group_vk}"))?;
    if signature.len() != FROST_SIG_LEN {
        return Err(format!(
            "frost signature length {}, need {FROST_SIG_LEN}",
            signature.len()
        ));
    }
    let r = Point::decompress_slice(&signature[..FROST_R_LEN])
        .ok_or_else(|| "frost signature R is not a secp256k1 point".to_string())?;
    let mut z_bytes = [0u8; FROST_Z_LEN];
    z_bytes.copy_from_slice(&signature[FROST_R_LEN..]);
    let z = Scalar::from_canonical_bytes(&z_bytes)
        .ok_or_else(|| "frost signature z is not a canonical scalar".to_string())?;
    let parsed = Signature { r, z };
    if osst::frost::verify_signature(&group, message, &parsed) {
        Ok(())
    } else {
        Err(format!(
            "frost signature rejected for group_vk {group_vk} message_len {}",
            message.len()
        ))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

fn decode_hex(group_vk: &str) -> Option<Vec<u8>> {
    let bytes = group_vk.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
