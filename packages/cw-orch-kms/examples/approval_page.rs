//! Loopback page for one cw-orch approval. Open the printed URL, scan the
//! code with Zigner on the Terp key (account 0), and paste the signature.

use std::sync::Arc;

use cw_orch_kms::{
    listen, ApprovalView, Principal, SignDocDigest, SigningRequest, TestApprover, MSG_EXECUTE,
    MSG_STORE_CODE,
};

#[tokio::main]
async fn main() {
    let digest = "ab".repeat(32);
    let view = ApprovalView {
        digest: SignDocDigest::new(digest).expect("64 hex"),
        principal: Principal::new("treasury").expect("principal"),
        messages: vec![
            SigningRequest::new(MSG_STORE_CODE)
                .code_id(7)
                .body(r#"{"wasm_byte_code":"AGFzbQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}"#),
            SigningRequest::new(MSG_EXECUTE)
                .contract("terp1contract")
                .body(r#"{"swap":{"denom":"uterp"},"payload":"eyJvayI6dHJ1ZX0="}"#),
        ],
    };
    let mut terminal = listen(
        "127.0.0.1:8741".parse().expect("addr"),
        view,
        Arc::new(TestApprover),
    )
    .await
    .expect("listen");
    println!("http://{}", terminal.addr());
    tokio::select! {
        outcome = terminal.outcome() => {
            println!("{outcome:?}");
            let _ = tokio::signal::ctrl_c().await;
        }
        _ = tokio::signal::ctrl_c() => {}
    }
}
