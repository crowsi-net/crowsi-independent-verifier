#[test]
fn sample_is_closed_local_only_json_with_verified_and_unknown() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_crowsi-independent-verifier"))
        .arg("sample")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "crowsi.verifier-conformance-sample.v1");
    assert_eq!(value["external_actions"], false);
    assert_eq!(value["verified"]["state"], "verified");
    assert_eq!(value["unknown"]["state"], "unknown");
}
