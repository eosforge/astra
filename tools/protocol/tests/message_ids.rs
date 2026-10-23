//! MessageID compatibility cases without network access or nested Cargo invocation.

use std::io;

/// Owns one exclusively created test registry file for best-effort cleanup.
struct TestLock(std::path::PathBuf);

impl Drop for TestLock {
    /// Attempts to remove only this test's registry file when the guard leaves scope.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// Reuse the standard-library-only allocator without linking the generator into services.
#[path = "../src/ids.rs"]
mod ids;

/// Reordering/removal preserve used IDs; new messages append only.
#[test]
fn append_only_ids_survive_reordering_and_removal() -> io::Result<()> {
    let previous = "2\tp.Hello\n7\tp.Removed\n";
    let current = ids::assign(previous, ["p.Pong".into(), "p.Hello".into(), "p.Ping".into()])?;
    assert_eq!(current.get(&2).map(String::as_str), Some("p.Hello"));
    assert_eq!(current.get(&7).map(String::as_str), Some("p.Removed"));
    assert_eq!(current.get(&8).map(String::as_str), Some("p.Ping"));
    assert_eq!(current.get(&9).map(String::as_str), Some("p.Pong"));
    Ok(())
}

/// Initial assignment is independent of declaration order.
#[test]
fn initial_assignment_is_deterministic() -> io::Result<()> {
    let first = ids::assign("", ["p.Pong".into(), "p.Hello".into()])?;
    let second = ids::assign("", ["p.Hello".into(), "p.Pong".into()])?;
    assert_eq!(first, second);
    assert_eq!(first.get(&1).map(String::as_str), Some("p.Hello"));
    Ok(())
}

/// Rejects conflicting, exhausted, or malformed registries without renumbering.
#[test]
fn conflicting_or_exhausted_ids_fail() {
    for previous in ["0 p.A", "1 p.A\n1 p.B", "1 p.A\n2 p.A", "65536 p.A", "1", "1 p.A extra", "65535 p.Old"] {
        assert!(ids::assign(previous, ["p.New".into()]).is_err(), "accepted invalid registry: {previous}");
    }
}

/// A stale registry changes only in explicit update mode; check mode preserves its bytes.
#[test]
fn ordinary_build_never_changes_stale_registry() -> io::Result<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/proto/test-locks");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("astra-ids-{}-{nonce}.lock", std::process::id()));
    std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
    let _cleanup = TestLock(path.clone());
    let previous = "1 p.Hello\n";
    let current = "1 p.Hello\n2 p.Ping\n";
    std::fs::write(&path, previous)?;
    assert!(ids::store(&path, previous, current, false).is_err());
    assert_eq!(std::fs::read_to_string(&path)?, previous);
    assert!(ids::store(&path, previous, current, true)?);
    assert_eq!(std::fs::read_to_string(&path)?, current);
    assert!(!ids::store(&path, current, current, false)?);
    Ok(())
}
