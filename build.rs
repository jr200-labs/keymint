fn main() {
    let manifest = ".release-please-manifest.json";
    println!("cargo:rerun-if-changed={manifest}");
    let release: serde_json::Value =
        serde_json::from_slice(&std::fs::read(manifest).expect("read release version manifest"))
            .expect("parse release version manifest");
    let version = release["."].as_str().expect("root release version");
    assert!(
        version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte)),
        "invalid release version"
    );
    println!("cargo:rustc-env=KEYMINT_VERSION=v{version}");
}
