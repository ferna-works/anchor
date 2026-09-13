use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use assert_cmd::{Command, assert::Assert};
use predicates::str::contains;
use tempfile::TempDir;

const NOT_IN_CONTROL_SET: &str = "does not match any key in the current control set";
const DEVICE_NOT_AUTHORIZED: &str = "device is not authorized";
const IDENTITY_DEACTIVATED: &str = "identity is deactivated";

fn node() -> String {
    std::env::var("ANCHOR_DEMO_TEST_NODE").unwrap_or_else(|_| "http://127.0.0.1:26657".to_string())
}

fn genesis_path() -> PathBuf {
    if let Ok(path) = std::env::var("ANCHOR_DEMO_TEST_GENESIS") {
        return PathBuf::from(path);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.devenv/state/devnet/node0/config/genesis.json")
}

fn demo(dir: &Path, args: &[&str]) -> Assert {
    Command::cargo_bin("demo")
        .expect("demo binary should be built by `cargo test`")
        .current_dir(dir)
        .arg("--node")
        .arg(node())
        .args(args)
        .assert()
}

fn stdout(assert: &Assert) -> String {
    String::from_utf8_lossy(&assert.get_output().stdout).into_owned()
}

fn field(text: &str, label: &str) -> Option<String> {
    let prefix = format!("{label}: ");

    text.lines()
        .find_map(|line| line.trim_start().strip_prefix(prefix.as_str()))
        .map(str::to_string)
}

fn committed_height(assert: &Assert) -> u64 {
    stdout(assert)
        .lines()
        .find_map(|line| line.strip_prefix("✓ committed at height "))
        .and_then(|value| value.trim().parse().ok())
        .expect("committed-at-height line in success output")
}

fn read_after(min_height: u64, mut read: impl FnMut() -> Assert) -> Assert {
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let assert = read();
        let verified_height = field(&stdout(&assert), "verified at height")
            .and_then(|value| value.parse::<u64>().ok());

        if verified_height.is_some_and(|height| height > min_height) || Instant::now() >= deadline {
            return assert;
        }

        thread::sleep(Duration::from_millis(150));
    }
}

fn keygen(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    demo(dir, &["keygen", path.to_str().unwrap()]).success();

    path
}

fn pubkey(dir: &Path, path: &Path) -> String {
    let assert = demo(dir, &["pubkey", path.to_str().unwrap()]).success();

    stdout(&assert).trim().to_string()
}

struct Identity {
    id_hex: String,
    did: String,
    height: u64,
}

fn inception(dir: &Path, control: &Path, next_key_hex: &str) -> Identity {
    let genesis = genesis_path();
    let assert = demo(
        dir,
        &[
            "inception",
            "--key",
            control.to_str().unwrap(),
            "--next-key",
            next_key_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
    .success();

    let height = committed_height(&assert);
    let text = stdout(&assert);

    Identity {
        id_hex: field(&text, "identity id").expect("identity id in inception output"),
        did: field(&text, "did").expect("did in inception output"),
        height,
    }
}

fn fresh_identity(dir: &Path) -> (Identity, PathBuf, PathBuf) {
    let control = keygen(dir, "control.key");
    let next = keygen(dir, "next.key");
    let next_hex = pubkey(dir, &next);

    let identity = inception(dir, &control, &next_hex);

    (identity, control, next)
}

fn query(dir: &Path, id_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &["query", id_hex, "--genesis", genesis.to_str().unwrap()],
    )
}

fn history(dir: &Path, id_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &["history", id_hex, "--genesis", genesis.to_str().unwrap()],
    )
}

fn resolve(dir: &Path, did: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &["resolve", did, "--genesis", genesis.to_str().unwrap()],
    )
}

fn authorize_device(dir: &Path, id_hex: &str, key: &Path, device_key_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "authorize-device",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--device-key",
            device_key_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

fn revoke_device(dir: &Path, id_hex: &str, key: &Path, device_id_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "revoke-device",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--device-id",
            device_id_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn rotate_control(
    dir: &Path,
    id_hex: &str,
    key: &Path,
    reveal_key_hex: &str,
    next_key_hex: &str,
) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "rotate-control",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--reveal-key",
            reveal_key_hex,
            "--next-key",
            next_key_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

fn commit_credential(dir: &Path, id_hex: &str, key: &Path, credential_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "commit-credential",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--credential",
            credential_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

fn revoke_credential(dir: &Path, id_hex: &str, key: &Path, credential_hex: &str) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "revoke-credential",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--credential",
            credential_hex,
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

fn deactivate(dir: &Path, id_hex: &str, key: &Path) -> Assert {
    let genesis = genesis_path();

    demo(
        dir,
        &[
            "deactivate",
            id_hex,
            "--key",
            key.to_str().unwrap(),
            "--genesis",
            genesis.to_str().unwrap(),
        ],
    )
}

#[test]
fn keygen_and_pubkey_round_trip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice.key");

    let assert = demo(dir.path(), &["keygen", path.to_str().unwrap()]).success();
    let reported = field(&stdout(&assert), "public key").expect("public key in keygen output");
    let printed = pubkey(dir.path(), &path);

    assert_eq!(reported, printed);
    assert_eq!(
        printed.len(),
        64,
        "an ed25519 public key is 32 bytes of hex"
    );
}

#[test]
fn keygen_refuses_to_overwrite_without_force() {
    let dir = TempDir::new().unwrap();
    let path = keygen(dir.path(), "alice.key");
    let first_pubkey = pubkey(dir.path(), &path);

    demo(dir.path(), &["keygen", path.to_str().unwrap()])
        .failure()
        .stderr(contains("already exists"));

    assert_eq!(
        pubkey(dir.path(), &path),
        first_pubkey,
        "a rejected keygen must not touch the existing file"
    );

    demo(dir.path(), &["keygen", path.to_str().unwrap(), "--force"]).success();
}

#[test]
fn pubkey_rejects_a_missing_key_file() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("missing.key");

    demo(dir.path(), &["pubkey", missing.to_str().unwrap()])
        .failure()
        .stderr(contains("could not read key file"));
}

#[test]
#[ignore = "requires a running local devnet"]
fn inception_creates_an_identity_queryable_immediately() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());
    let control_pubkey = pubkey(dir.path(), &control);

    let assert = read_after(identity.height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert_eq!(field(&text, "did").as_deref(), Some(identity.did.as_str()));
    assert_eq!(
        field(&text, "status").as_deref(),
        Some("found (existence proof verified)")
    );
    assert_eq!(field(&text, "sequence").as_deref(), Some("0"));
    assert_eq!(field(&text, "deactivated").as_deref(), Some("false"));
    assert_eq!(field(&text, "control threshold").as_deref(), Some("1 of 1"));
    assert_eq!(
        field(&text, "control key[0]").as_deref(),
        Some(control_pubkey.as_str())
    );
}

#[test]
#[ignore = "requires a running local devnet"]
fn query_reports_not_found_for_an_unknown_identity() {
    let dir = TempDir::new().unwrap();
    let unknown = keygen(dir.path(), "unknown.key");
    let unknown_id_hex = pubkey(dir.path(), &unknown);

    let assert = query(dir.path(), &unknown_id_hex).success();
    let text = stdout(&assert);

    assert_eq!(
        field(&text, "status").as_deref(),
        Some("not found (absence proof verified)")
    );
}

#[test]
#[ignore = "requires a running local devnet"]
fn authorize_device_appears_in_subsequent_query() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());

    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);

    let assert =
        authorize_device(dir.path(), &identity.id_hex, &control, &device_key_hex).success();
    let height = committed_height(&assert);

    let assert = read_after(height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert_eq!(field(&text, "sequence").as_deref(), Some("1"));

    let device_field = field(&text, "device").expect("device line in query output");
    assert!(device_field.contains(&device_key_hex));
}

#[test]
#[ignore = "requires a running local devnet"]
fn authorize_device_rejects_a_signer_outside_the_control_set() {
    let dir = TempDir::new().unwrap();
    let (identity, _control, _next) = fresh_identity(dir.path());

    let outsider = keygen(dir.path(), "outsider.key");
    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);

    authorize_device(dir.path(), &identity.id_hex, &outsider, &device_key_hex)
        .failure()
        .stderr(contains(NOT_IN_CONTROL_SET));
}

#[test]
#[ignore = "requires a running local devnet"]
fn rotate_control_requires_the_revealed_key_not_the_current_one() {
    let dir = TempDir::new().unwrap();
    let (identity, control, next) = fresh_identity(dir.path());
    let next_hex = pubkey(dir.path(), &next);
    let following = keygen(dir.path(), "following.key");
    let following_hex = pubkey(dir.path(), &following);

    rotate_control(
        dir.path(),
        &identity.id_hex,
        &control,
        &next_hex,
        &following_hex,
    )
    .failure()
    .stderr(contains(NOT_IN_CONTROL_SET));
}

#[test]
#[ignore = "requires a running local devnet"]
fn rotate_control_updates_the_control_key_and_clears_devices() {
    let dir = TempDir::new().unwrap();
    let (identity, control, next) = fresh_identity(dir.path());
    let next_hex = pubkey(dir.path(), &next);

    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);
    authorize_device(dir.path(), &identity.id_hex, &control, &device_key_hex).success();

    let following = keygen(dir.path(), "following.key");
    let following_hex = pubkey(dir.path(), &following);

    let assert = rotate_control(
        dir.path(),
        &identity.id_hex,
        &next,
        &next_hex,
        &following_hex,
    )
    .success();
    let height = committed_height(&assert);

    let assert = read_after(height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert_eq!(field(&text, "sequence").as_deref(), Some("2"));
    assert_eq!(
        field(&text, "control key[0]").as_deref(),
        Some(next_hex.as_str())
    );
    assert!(
        !text.contains("  device:"),
        "rotating control must clear previously authorized devices, got:\n{text}"
    );
}

#[test]
#[ignore = "requires a running local devnet"]
fn revoke_device_removes_it_from_subsequent_query() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());

    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);
    let assert =
        authorize_device(dir.path(), &identity.id_hex, &control, &device_key_hex).success();
    let authorized_height = committed_height(&assert);

    let assert = read_after(authorized_height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);
    let device_field = field(&text, "device").expect("device line after authorization");
    let device_id_hex = device_field
        .split(' ')
        .next()
        .expect("device field starts with the device id")
        .to_string();

    let assert = revoke_device(dir.path(), &identity.id_hex, &control, &device_id_hex).success();
    let revoked_height = committed_height(&assert);

    let assert = read_after(revoked_height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert!(!text.contains("  device:"));
    assert_eq!(field(&text, "sequence").as_deref(), Some("2"));
}

#[test]
#[ignore = "requires a running local devnet"]
fn revoke_device_rejects_an_unknown_device_id() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());

    let bogus = keygen(dir.path(), "bogus.key");
    let bogus_id_hex = pubkey(dir.path(), &bogus);

    revoke_device(dir.path(), &identity.id_hex, &control, &bogus_id_hex)
        .failure()
        .stderr(contains(DEVICE_NOT_AUTHORIZED));
}

#[test]
#[ignore = "requires a running local devnet"]
fn deactivate_marks_identity_deactivated_and_blocks_further_events() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());

    let assert = deactivate(dir.path(), &identity.id_hex, &control).success();
    let height = committed_height(&assert);

    let assert = read_after(height, || query(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);
    assert_eq!(field(&text, "deactivated").as_deref(), Some("true"));

    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);

    authorize_device(dir.path(), &identity.id_hex, &control, &device_key_hex)
        .failure()
        .stderr(contains(IDENTITY_DEACTIVATED));
}

#[test]
#[ignore = "requires a running local devnet"]
fn history_lists_events_in_order() {
    let dir = TempDir::new().unwrap();
    let (identity, control, next) = fresh_identity(dir.path());
    let next_hex = pubkey(dir.path(), &next);

    let device = keygen(dir.path(), "device.key");
    let device_key_hex = pubkey(dir.path(), &device);
    authorize_device(dir.path(), &identity.id_hex, &control, &device_key_hex).success();

    let following = keygen(dir.path(), "following.key");
    let following_hex = pubkey(dir.path(), &following);
    let assert = rotate_control(
        dir.path(),
        &identity.id_hex,
        &next,
        &next_hex,
        &following_hex,
    )
    .success();
    let height = committed_height(&assert);

    let assert = read_after(height, || history(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert_eq!(field(&text, "events").as_deref(), Some("3"));

    let event_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("event["))
        .collect();

    assert_eq!(event_lines.len(), 3);
    assert!(event_lines[0].contains("(inception)"));
    assert!(event_lines[1].contains("(authorize device)"));
    assert!(event_lines[2].contains("(rotate control)"));
}

#[test]
#[ignore = "requires a running local devnet"]
fn commit_credential_then_revoke_credential_appear_in_history_in_order() {
    let dir = TempDir::new().unwrap();
    let (identity, control, _next) = fresh_identity(dir.path());
    let credential_hex = "cc".repeat(32);

    commit_credential(dir.path(), &identity.id_hex, &control, &credential_hex).success();
    let assert =
        revoke_credential(dir.path(), &identity.id_hex, &control, &credential_hex).success();
    let height = committed_height(&assert);

    let assert = read_after(height, || history(dir.path(), &identity.id_hex)).success();
    let text = stdout(&assert);

    assert_eq!(field(&text, "events").as_deref(), Some("3"));

    let event_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.trim_start().starts_with("event["))
        .collect();

    assert_eq!(event_lines.len(), 3);
    assert!(event_lines[0].contains("(inception)"));
    assert!(event_lines[1].contains("(commit credential)"));
    assert!(event_lines[2].contains("(revoke credential)"));
}

#[test]
#[ignore = "requires a running local devnet"]
fn resolve_returns_a_did_document_for_the_current_control_key() {
    let dir = TempDir::new().unwrap();
    let (identity, _control, _next) = fresh_identity(dir.path());

    let assert = read_after(identity.height, || resolve(dir.path(), &identity.did)).success();
    let text = stdout(&assert);

    assert!(text.contains(&format!("\"id\": \"{}\"", identity.did)));
    assert!(text.contains("#control-0"));
    assert!(text.contains("Ed25519VerificationKey2020"));
}
