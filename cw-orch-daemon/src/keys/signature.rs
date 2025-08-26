use crate::DaemonError;
use base64::engine::{general_purpose::STANDARD, Engine};
use bitcoin::secp256k1::{Message, Secp256k1};
use ring::digest::SHA256;
pub struct Signature {}
impl Signature {
    pub fn verify<C: bitcoin::secp256k1::Verification + bitcoin::secp256k1::Context>(
        secp: &Secp256k1<C>,
        pub_key: &str,
        signature: &str,
        blob: &str,
    ) -> Result<(), DaemonError> {
        let public = STANDARD.decode(pub_key)?;
        let sig = STANDARD.decode(signature)?;
        let pk = bitcoin::secp256k1::PublicKey::from_slice(public.as_slice())?;
        let sha_result = ring::digest::digest(&SHA256, blob.as_bytes());
        let message: Message = Message::from_digest_slice(&sha_result.as_ref()[0..32])?;
        let secp_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(sig.as_slice())?;
        secp.verify_ecdsa(&message, &secp_sig, &pk)?;
        Ok(())
    }
}
#[cfg(test)]
mod tst {
    use cosmwasm_std::StdResult;

    use super::*;
    #[test]
    pub fn test_verify() -> StdResult<()> {
        let secp = Secp256k1::new();

        let message = r#"{"account_number":"45","chain_id":"columbus-3-testnet","fee":{"amount":[{"amount":"698","denom":"uluna"}],"gas":"46467"},"memo":"","msgs":[{"type":"bank/MsgSend","value":{"amount":[{"amount":"100000000","denom":"uluna"}],"from_address":"terra1n3g37dsdlv7ryqftlkef8mhgqj4ny7p8v78lg7","to_address":"terra1wg2mlrxdmnnkkykgqg4znky86nyrtc45q336yv"}}],"sequence":"0"}"#;
        let signature = "FJKAXRxNB5ruqukhVqZf3S/muZEUmZD10fVmWycdVIxVWiCXXFsUy2VY2jINEOUGNwfrqEZsT2dUfAvWj8obLg==";
        let pub_key = "AiMzHaA2bvnDXfHzkjMM+vkSE/p0ymBtAFKUnUtQAeXe";
        Signature::verify(&secp, pub_key, signature, message)?;
        Ok(())
    }
}
