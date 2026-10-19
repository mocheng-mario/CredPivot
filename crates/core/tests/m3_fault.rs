use credpivot_core::{bootstrap_vault_dir, clone_vault_to_empty_dir};
use tempfile::tempdir;

#[test]
fn migrate_rejects_nonempty_target() {
    let src = tempdir().expect("src");
    let material = bootstrap_vault_dir(src.path(), "pw").expect("bootstrap");
    let target = tempdir().expect("target");
    std::fs::write(target.path().join("marker.txt"), b"x").expect("marker");
    let err = clone_vault_to_empty_dir(src.path(), target.path(), &material.vmk).expect_err("fail");
    let msg = err.to_string();
    assert!(msg.contains("not empty") || msg.contains("target"));
}
