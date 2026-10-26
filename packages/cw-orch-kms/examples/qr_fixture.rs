//! Zigner multi-frame Cosmos fixture generator (test data only).
//!
//! `cargo run --example qr_fixture -- --out DIR [--frame-bytes N] [--msg-file F]`
//!
//! Builds a session-key operator-exec amino sign doc on the local rehearsal
//! chain `deploy-rehearsal-1` (mock addresses only), wraps it in the 530510
//! Zigner request exactly as the approval page does (`zigner_qr_hex`), splits
//! it with `raptor_frames`, writes payload/frames/meta and self-checks decoding.

use cw_orch_kms::{canonical_json, exec_contract_as, raptor_frames, set_approval_chain, zigner_qr_hex, ChainProfile, ZIGNER_FRAME_BYTES};
use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const CHAIN_ID: &str = "deploy-rehearsal-1";
// Local rehearsal-chain mock-phone addresses (throwaway 127.0.0.1 chain).
const GRANTER: &str = "terp10h8n86cm64m00rvwkpx8v49dkvk8eyqdg43wtr";
const OPERATOR: &str = "terp1hlkc28uyc906mz2757960pjxsjdya8adzhzc5q";
const SESSION_KEY: &str = "terp180g7fkq6cgclcn9vus2sax9y9l6evghj6uujze";
const FACTORY: &str = "terp1765mhu6tvkg3mgqtxgv6973t6g3p25jpwjah5lmckx7nv99jv5tswdjeu6";
const DEFAULT_MSG: &str = include_str!("fixtures/create_svg_collection.json");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn decode<'a>(frames: impl Iterator<Item = &'a Vec<u8>>) -> Option<Vec<u8>> {
    let mut dec: Option<Decoder> = None;
    for f in frames {
        let len = u32::from_be_bytes([f[0] & 0x7f, f[1], f[2], f[3]]);
        assert!(f[0] & 0x80 != 0, "header top bit not set");
        let p = EncodingPacket::deserialize(&f[4..]);
        let d = dec.get_or_insert_with(|| {
            Decoder::new(ObjectTransmissionInformation::with_defaults(len as u64, (f.len() - 8) as u16))
        });
        if let Some(out) = d.decode(p) {
            return Some(out);
        }
    }
    None
}

fn main() -> Result<(), String> {
    let mut out: Option<PathBuf> = None;
    let mut chunk = ZIGNER_FRAME_BYTES;
    let mut msg_text = DEFAULT_MSG.to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            "--frame-bytes" => chunk = args.next().and_then(|v| v.parse().ok()).ok_or("--frame-bytes N")?,
            "--msg-file" => msg_text = std::fs::read_to_string(args.next().ok_or("--msg-file F")?).map_err(|e| e.to_string())?,
            _ => return Err(format!("unknown arg {a}; usage: --out DIR [--frame-bytes N] [--msg-file F]")),
        }
    }
    let out = out.ok_or("usage: --out DIR [--frame-bytes N] [--msg-file F]")?;
    if chunk < 64 {
        return Err("--frame-bytes must be >= 64".into());
    }
    set_approval_chain(ChainProfile::new(CHAIN_ID, "terp", "uthiol", 0.05, "terp", "Terp rehearsal"))?;

    let msg: serde_json::Value = serde_json::from_str(&msg_text).map_err(|e| e.to_string())?;
    let inner = exec_contract_as(OPERATOR, GRANTER, FACTORY, &msg, &[])?;
    let outer = format!(
        "{{\"type\":\"cosmos-sdk/MsgExec\",\"value\":{{\"grantee\":\"{SESSION_KEY}\",\"msgs\":[{}]}}}}",
        inner.amino
    );
    let doc = serde_json::json!({
        "account_number": "17",
        "chain_id": CHAIN_ID,
        "fee": {"amount": [{"amount": "85290", "denom": "uthiol"}], "gas": "1705796", "granter": OPERATOR},
        "memo": "",
        "msgs": [serde_json::from_str::<serde_json::Value>(&outer).map_err(|e| e.to_string())?],
        "sequence": "0",
    });
    let sign_doc = canonical_json(&doc);
    let payload = unhex(&zigner_qr_hex(0, sign_doc.as_bytes()));
    assert!(payload.starts_with(&[0x53, 0x05, 0x10]), "payload is not 530510");
    if payload.len() <= 2953 {
        return Err(format!("payload only {} bytes; fixture must exceed 2953", payload.len()));
    }
    let frames = raptor_frames(&payload, chunk)?;
    // raptorq rounds the symbol size down to its 8-byte alignment (300 -> 296).
    let symbol = raptorq::Encoder::with_defaults(&payload, chunk).get_config().symbol_size() as usize;
    let source = payload.len().div_ceil(symbol);
    let repair_requested = payload.len() / chunk as usize;
    // raptorq may pad/split per source block, so count what was emitted.
    let repair = frames.len() - source;

    // Self-checks.
    assert_eq!(decode(frames.iter()).as_deref(), Some(&payload[..]), "all frames");
    assert_eq!(decode(frames.iter().skip(5)).as_deref(), Some(&payload[..]), "skip first 5");
    let every_other: Vec<_> = frames.iter().enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, f)| f).collect();
    let ok_alt = repair >= source / 2 && every_other.len() >= source;
    if ok_alt {
        assert_eq!(decode(every_other.into_iter()).as_deref(), Some(&payload[..]), "odd frames only");
    }
    assert_eq!(decode(frames.iter().rev()).as_deref(), Some(&payload[..]), "reversed");
    assert!(decode(frames.iter().take(source - 1)).is_none(), "decoded from too few frames");

    let fdir = out.join("frames");
    std::fs::create_dir_all(&fdir).map_err(|e| e.to_string())?;
    let w = |p: PathBuf, b: &[u8]| std::fs::write(&p, b).map_err(|e| format!("{}: {e}", p.display()));
    w(out.join("payload.bin"), &payload)?;
    w(out.join("payload.hex"), format!("{}\n", hex(&payload)).as_bytes())?;
    w(out.join("sign_doc.json"), sign_doc.as_bytes())?;
    let mut list = String::new();
    for (i, f) in frames.iter().enumerate() {
        w(fdir.join(format!("{i:03}.bin")), f)?;
        list.push_str(&hex(f));
        list.push('\n');
    }
    w(fdir.join("frames.hex"), list.as_bytes())?;

    let enc = raptorq::Encoder::with_defaults(&payload, chunk);
    let oti = enc.get_config();
    let meta = serde_json::json!({
        "chain_id": CHAIN_ID,
        "payload_len": payload.len(),
        "payload_prefix_hex": hex(&payload[..3]),
        "payload_sha256": hex(&Sha256::digest(&payload)),
        "sign_doc_len": sign_doc.len(),
        "sign_doc_sha256": hex(&Sha256::digest(sign_doc.as_bytes())),
        "account_index": 0,
        "zigner_chain_name": "terp",
        "frame_bytes_requested": chunk,
        "symbol_size": symbol,
        "frame_len": frames[0].len(),
        "frame_count": frames.len(),
        "source_frames": source,
        "repair_frames": repair,
        "repair_requested": repair_requested,
        "emission_order": "frames/000.bin .. in order; per source block: source packets (ESI 0..K-1) then repair packets; see raptorq_oti.source_blocks",
        "header": {"len": 4, "format": "big-endian u32; top bit set (0x80000000); low 31 bits = payload_len",
                   "value_hex": hex(&(payload.len() as u32 | 0x8000_0000).to_be_bytes())},
        "packet": "raptorq 1.8 EncodingPacket::serialize(): 4-byte PayloadId (SBN u8, ESI u24 BE) + symbol (frame_bytes)",
        "raptorq_oti": {
            "constructor": "Encoder::with_defaults(payload, frame_bytes); decoder: ObjectTransmissionInformation::with_defaults(payload_len, frame_len - 8)",
            "transfer_length": oti.transfer_length(),
            "symbol_size": oti.symbol_size(),
            "source_blocks": oti.source_blocks(),
            "sub_blocks": oti.sub_blocks(),
            "symbol_alignment": oti.symbol_alignment(),
            "serialized_hex": hex(&oti.serialize()),
        },
        "self_check": {"all": true, "skip_first_5": true, "reversed": true, "odd_frames_only": ok_alt, "fails_with_source_minus_1": true},
        "addresses_note": "mock addresses from the throwaway local chain deploy-rehearsal-1; no real keys",
    });
    w(out.join("meta.json"), serde_json::to_string_pretty(&meta).unwrap().as_bytes())?;
    println!("{}: payload {} bytes sha256 {} -> {} frames ({} source + {} repair) of {} bytes; self-check ok",
        out.display(), payload.len(), hex(&Sha256::digest(&payload)), frames.len(), source, repair, frames[0].len());
    Ok(())
}
