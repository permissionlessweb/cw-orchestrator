// Point ui_shared's vendored paths (zxing) at packages/cw-orch-kms, the same
// files the Cosmos pages serve. Compile-time only.
fn main() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    println!("cargo:rustc-env=CW_ORCH_KMS_DIR={}", dir.display());
    println!("cargo:rerun-if-changed=build.rs");
}
