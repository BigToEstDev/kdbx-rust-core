//! The life cycle of a database across the boundary: create, read, save, close.
//!
//! Nothing here touches a file. The bytes travel in and out exactly as they do on Android, where the file
//! belongs to SAF and this library never sees a path - so the test exercises the app's own path, on the
//! host, without a device. It also pins the shape of every answer through `contract`.

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    db_key_args, key_of, new_db_args, prepare, read_args, KDBX_SIGNATURE, TEST_PASSWORD,
};

#[test]
fn a_database_is_created_read_saved_and_closed() {
    prepare();
    let db_key = key_of("round-trip");

    // Create: the bytes of a brand new database come back for Kotlin to write through SAF
    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    assert!(
        created
            .envelope
            .contains(&format!(r#""db_key":"{}""#, db_key)),
        "{}",
        created.envelope
    );
    assert_shape("create_and_write_to_writer", &created.envelope);

    let bytes = created
        .payload
        .expect("the new database has to come back as bytes");
    assert_eq!(&bytes[..4], &KDBX_SIGNATURE, "not a kdbx file");

    // Close it, so reading it back goes through the real path rather than the cache
    let closed = run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
    assert!(
        closed.envelope.contains(r#""done":true"#),
        "{}",
        closed.envelope
    );
    assert_shape("close_kdbx", &closed.envelope);

    // Read: the same bytes, the password, and the display name the app knows
    let read = run_with_bytes("read_kdbx", &read_args(&db_key, "open sesame"), Some(bytes));
    assert!(
        read.envelope.contains(r#""database_name":"Test""#),
        "{}",
        read.envelope
    );
    assert!(
        read.envelope.contains(r#""file_name":"lifecycle.kdbx""#),
        "the name the app passed in has to come back, not one derived from the uri: {}",
        read.envelope
    );
    assert!(read.payload.is_none(), "reading produces no bytes");
    assert_shape("read_kdbx", &read.envelope);

    // Save: a fresh serialisation of what is in memory now
    let saved = run_with_bytes("save_kdbx_to_writer", &db_key_args(&db_key), None);
    assert_shape("save_kdbx_to_writer", &saved.envelope);
    let saved_bytes = saved.payload.expect("saving has to produce the file");
    assert_eq!(&saved_bytes[..4], &KDBX_SIGNATURE, "not a kdbx file");

    // The saved bytes open again. Their equality with the original is not the point and would not hold:
    // every save rewrites the encrypted payload with fresh randomness
    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
    let reread = run_with_bytes(
        "read_kdbx",
        &read_args(&db_key, "open sesame"),
        Some(saved_bytes),
    );
    assert!(
        reread.envelope.contains(r#""database_name":"Test""#),
        "{}",
        reread.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

#[test]
fn a_wrong_password_is_a_failure_with_its_own_kind_and_not_a_panic() {
    prepare();
    let db_key = key_of("wrong-password");

    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    let bytes = created.payload.expect("the new database has to come back");
    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);

    let answer = run_with_bytes(
        "read_kdbx",
        &read_args(&db_key, "not the password"),
        Some(bytes),
    );

    assert!(
        answer.envelope.starts_with(r#"{"err":"#),
        "{}",
        answer.envelope
    );
    // Exactly this kind: the app branches on it to tell a typo in the password from a file it will never
    // open (Step 30). Before, the kind was HeaderHmacHashCheckFailed and the meaning was in the message
    assert!(
        answer.envelope.contains(r#""kind":"InvalidCredentials""#),
        "the kind has to name what went wrong: {}",
        answer.envelope
    );
    assert!(answer.payload.is_none(), "a refusal carries no payload");
}

// A file cut short - a sync that did not finish - reaches the app as corrupted wherever it ends (Step 30)
#[test]
fn a_truncated_file_is_corrupted_and_not_a_failure_of_the_app() {
    prepare();
    let db_key = key_of("truncated");

    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    let bytes = created.payload.expect("the new database has to come back");
    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);

    for (cut, kind) in [
        (100, "HeaderCorrupted"),
        (bytes.len() - 10, "ContentCorrupted"),
    ] {
        let answer = run_with_bytes(
            "read_kdbx",
            &read_args(&db_key, TEST_PASSWORD),
            Some(bytes[..cut].to_vec()),
        );
        assert!(
            answer.envelope.contains(&format!(r#""kind":"{}""#, kind)),
            "cut at {}: {}",
            cut,
            answer.envelope
        );
    }
}

#[test]
fn reading_without_the_bytes_of_a_file_is_refused() {
    prepare();

    let answer = run_with_bytes("read_kdbx", &db_key_args(&key_of("no-bytes")), None);

    assert!(
        answer.envelope.contains(r#""kind":"InvalidArguments""#),
        "{}",
        answer.envelope
    );
}

#[test]
fn an_operation_on_a_database_that_is_not_open_says_so() {
    prepare();

    let answer = run_with_bytes(
        "save_kdbx_to_writer",
        r#"{"db_key":"content://test/never-opened.kdbx"}"#,
        None,
    );

    assert!(
        answer.envelope.starts_with(r#"{"err":"#),
        "{}",
        answer.envelope
    );
    assert!(
        answer.envelope.contains("DbKeyNotFound"),
        "{}",
        answer.envelope
    );
}

#[test]
fn arguments_without_a_db_key_are_refused_rather_than_defaulted() {
    prepare();

    let answer = run_with_bytes("close_kdbx", "{}", None);

    assert!(
        answer.envelope.contains(r#""kind":"InvalidArguments""#),
        "{}",
        answer.envelope
    );
}

#[test]
fn a_database_is_locked_and_unlocked_with_the_same_credentials() {
    prepare();
    let db_key = key_of("lock-unlock");

    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    assert!(
        created.envelope.starts_with(r#"{"ok":"#),
        "{}",
        created.envelope
    );

    // Freshly opened: held by the core and not locked
    let opened = run_with_bytes("is_db_opened", &db_key_args(&db_key), None);
    assert_shape("is_db_opened", &opened.envelope);
    assert!(
        opened.envelope.contains(r#""opened":true"#),
        "{}",
        opened.envelope
    );

    let locked_before = run_with_bytes("is_db_locked", &db_key_args(&db_key), None);
    assert_shape("is_db_locked", &locked_before.envelope);
    assert!(
        locked_before.envelope.contains(r#""locked":false"#),
        "{}",
        locked_before.envelope
    );

    let lock = run_with_bytes("lock_kdbx", &db_key_args(&db_key), None);
    assert_shape("lock_kdbx", &lock.envelope);
    let locked_after = run_with_bytes("is_db_locked", &db_key_args(&db_key), None);
    assert!(
        locked_after.envelope.contains(r#""locked":true"#),
        "{}",
        locked_after.envelope
    );

    // A wrong password is refused, and the database stays locked rather than half open
    let refused = run_with_bytes(
        "unlock_kdbx",
        r#"{"db_key":"content://test/lock-unlock.kdbx","password":"not the password"}"#,
        None,
    );
    assert!(
        refused.envelope.starts_with(r#"{"err":"#),
        "{}",
        refused.envelope
    );
    let still_locked = run_with_bytes("is_db_locked", &db_key_args(&db_key), None);
    assert!(
        still_locked.envelope.contains(r#""locked":true"#),
        "a refused unlock leaves the database locked: {}",
        still_locked.envelope
    );

    let unlock = run_with_bytes(
        "unlock_kdbx",
        r#"{"db_key":"content://test/lock-unlock.kdbx","password":"open sesame"}"#,
        None,
    );
    assert_shape("unlock_kdbx", &unlock.envelope);
    assert!(
        unlock.envelope.contains(r#""database_name":"Test""#),
        "{}",
        unlock.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

// The question exists to be asked about a database that may be gone - after the process was killed,
// the app has a uri in its list and nothing in the core
#[test]
fn the_password_of_an_open_database_is_checked_alone() {
    prepare();
    let db_key = key_of("verify-password");
    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    assert!(
        created.envelope.starts_with(r#"{"ok":"#),
        "{}",
        created.envelope
    );

    let args =
        |password: &str| serde_json::json!({ "db_key": db_key, "password": password }).to_string();
    let right = run_with_bytes("verify_password", &args(TEST_PASSWORD), None);
    assert_shape("verify_password", &right.envelope);
    assert!(
        right.envelope.contains(r#""matches":true"#),
        "{}",
        right.envelope
    );

    // A wrong one is an answer, not a failure: the screen shows it under the field
    let wrong = run_with_bytes("verify_password", &args("not the password"), None);
    assert!(
        wrong.envelope.contains(r#""matches":false"#),
        "{}",
        wrong.envelope
    );

    let used = run_with_bytes("credentials_used", &db_key_args(&db_key), None);
    assert_shape("credentials_used", &used.envelope);
    assert!(
        used.envelope.contains(r#""password":true"#)
            && used.envelope.contains(r#""key_file":false"#),
        "{}",
        used.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

#[test]
fn asking_whether_a_database_is_open_never_fails() {
    prepare();

    let answer = run_with_bytes(
        "is_db_opened",
        r#"{"db_key":"content://test/not-open-at-all.kdbx"}"#,
        None,
    );

    assert!(
        answer.envelope.starts_with(r#"{"ok":"#),
        "{}",
        answer.envelope
    );
    assert!(
        answer.envelope.contains(r#""opened":false"#),
        "a database that is not open answers false rather than failing: {}",
        answer.envelope
    );
}

#[test]
fn the_file_can_move_to_another_uri() {
    prepare();
    let db_key = key_of("rename-before");
    let new_db_key = key_of("rename-after");

    run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);

    let renamed = run_with_bytes(
        "rename_db_key",
        &format!(
            r#"{{"old_db_key":"{}","new_db_key":"{}"}}"#,
            db_key, new_db_key
        ),
        None,
    );
    assert_shape("rename_db_key", &renamed.envelope);
    assert!(
        renamed
            .envelope
            .contains(&format!(r#""db_key":"{}""#, new_db_key)),
        "{}",
        renamed.envelope
    );

    // The core knows it by the new name now, and not by the old one
    let under_new = run_with_bytes("is_db_opened", &db_key_args(&new_db_key), None);
    assert!(
        under_new.envelope.contains(r#""opened":true"#),
        "{}",
        under_new.envelope
    );
    let under_old = run_with_bytes("is_db_opened", &db_key_args(&db_key), None);
    assert!(
        under_old.envelope.contains(r#""opened":false"#),
        "{}",
        under_old.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&new_db_key), None);
}

#[test]
fn an_edit_makes_a_save_pending_and_saving_clears_it() {
    prepare();
    let db_key = key_of("save-pending");

    run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);

    let fresh = run_with_bytes("kdbx_context_statuses", &db_key_args(&db_key), None);
    assert_shape("kdbx_context_statuses", &fresh.envelope);
    assert!(
        fresh.envelope.contains(r#""save_pending":false"#),
        "a database just written has nothing pending: {}",
        fresh.envelope
    );

    // Any change to the content is enough - a group is the cheapest one
    let group = run_with_bytes("new_blank_group", r#"{"mark_as_category":false}"#, None);
    let mut group: serde_json::Value = crate::test_support::ok_payload(&group.envelope);
    group["parent_group_uuid"] = serde_json::json!(root_of(&db_key));
    group["name"] = serde_json::json!("Pending");
    run_with_bytes(
        "insert_group",
        &serde_json::json!({"db_key": db_key, "group": group}).to_string(),
        None,
    );

    let after_edit = run_with_bytes("kdbx_context_statuses", &db_key_args(&db_key), None);
    assert!(
        after_edit.envelope.contains(r#""save_pending":true"#),
        "an edit has to be visible as pending, that is what an unsaved changes prompt reads: {}",
        after_edit.envelope
    );

    run_with_bytes("save_kdbx_to_writer", &db_key_args(&db_key), None);
    let after_save = run_with_bytes("kdbx_context_statuses", &db_key_args(&db_key), None);
    assert!(
        after_save.envelope.contains(r#""save_pending":false"#),
        "{}",
        after_save.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

fn root_of(db_key: &str) -> String {
    let tree = run_with_bytes("groups_summary_data", &db_key_args(db_key), None);

    crate::test_support::ok_payload(&tree.envelope)["root_uuid"]
        .as_str()
        .expect("the tree has to name its root")
        .to_string()
}

// The biometric prompt is Android's and happens before this command; what it does here is restore
// the content of a locked database without a password. The test is that the boundary carries it -
// the strength of the whole thing lives in the Keystore work in front of it, not here
#[test]
fn a_locked_database_is_unlocked_after_an_authentication_that_already_happened() {
    prepare();
    let db_key = key_of("biometric-unlock");

    run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    run_with_bytes("lock_kdbx", &db_key_args(&db_key), None);

    let unlocked = run_with_bytes(
        "unlock_kdbx_on_biometric_authentication",
        &db_key_args(&db_key),
        None,
    );
    assert_shape(
        "unlock_kdbx_on_biometric_authentication",
        &unlocked.envelope,
    );
    assert!(
        unlocked.envelope.contains(r#""database_name":"Test""#),
        "{}",
        unlocked.envelope
    );

    let locked = run_with_bytes("is_db_locked", &db_key_args(&db_key), None);
    assert!(
        locked.envelope.contains(r#""locked":false"#),
        "the database is open again: {}",
        locked.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

// --- Key file as content (Step 29) ---
//
// A key file is behind SAF on Android, so it crosses the boundary as content: base64 inside the json
// arguments, under `key_file`, next to the name to show back.

fn key_file_json(name: &str, content: &[u8]) -> serde_json::Value {
    serde_json::json!({ "name": name, "content": crate::key_file::encode(content) })
}

fn new_db_args_with(db_key: &str, key_file: serde_json::Value) -> String {
    let mut args: serde_json::Value = serde_json::from_str(&new_db_args(db_key)).unwrap();
    args["key_file"] = key_file;
    args.to_string()
}

fn credentials_args(db_key: &str, key_file: serde_json::Value) -> String {
    serde_json::json!({
        "db_key": db_key,
        "password": crate::test_support::TEST_PASSWORD,
        "key_file": key_file,
        "file_name": "lifecycle.kdbx",
    })
    .to_string()
}

fn new_key_file() -> Vec<u8> {
    run_with_bytes("generate_key_file", "", None)
        .payload
        .expect("a generated key file")
}

#[test]
fn a_database_with_a_key_file_is_created_read_and_unlocked_with_its_content() {
    prepare();
    let db_key = key_of("key-file-round-trip");
    let key_file = new_key_file();

    let created = run_with_bytes(
        "create_and_write_to_writer",
        &new_db_args_with(&db_key, key_file_json("new.keyx", &key_file)),
        None,
    );
    assert!(
        created.envelope.contains(r#""key_file_name":"new.keyx""#),
        "the name to show comes back: {}",
        created.envelope
    );
    let bytes = created.payload.expect("the new database");
    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);

    let read = run_with_bytes(
        "read_kdbx",
        &credentials_args(&db_key, key_file_json("new.keyx", &key_file)),
        Some(bytes),
    );
    assert!(read.envelope.starts_with(r#"{"ok":"#), "{}", read.envelope);

    run_with_bytes("lock_kdbx", &db_key_args(&db_key), None);
    let unlocked = run_with_bytes(
        "unlock_kdbx",
        &credentials_args(&db_key, key_file_json("new.keyx", &key_file)),
        None,
    );
    assert!(
        unlocked.envelope.starts_with(r#"{"ok":"#),
        "{}",
        unlocked.envelope
    );

    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);
}

#[test]
fn a_database_with_a_key_file_is_not_opened_without_it_or_with_another_one() {
    prepare();
    let db_key = key_of("key-file-guard");
    let key_file = new_key_file();
    let other = new_key_file();

    let bytes = run_with_bytes(
        "create_and_write_to_writer",
        &new_db_args_with(&db_key, key_file_json("new.keyx", &key_file)),
        None,
    )
    .payload
    .expect("the new database");
    run_with_bytes("close_kdbx", &db_key_args(&db_key), None);

    for key_file in [serde_json::Value::Null, key_file_json("other.keyx", &other)] {
        let refused = run_with_bytes(
            "read_kdbx",
            &credentials_args(&db_key, key_file),
            Some(bytes.clone()),
        );
        assert!(
            refused.envelope.contains("InvalidCredentials"),
            "{}",
            refused.envelope
        );
    }
}

#[test]
fn a_key_file_over_the_limit_is_refused_with_its_own_kind() {
    prepare();
    let db_key = key_of("key-file-too-large");
    let content = vec![0u8; kdbx_rust_core::db_service::KEY_FILE_MAX_SIZE as usize + 1];

    let refused = run_with_bytes(
        "create_and_write_to_writer",
        &new_db_args_with(&db_key, key_file_json("video.mp4", &content)),
        None,
    );

    assert!(
        refused.envelope.contains(r#""kind":"KeyFileTooLarge""#),
        "{}",
        refused.envelope
    );
}

#[test]
fn a_key_file_path_is_refused_on_creating() {
    prepare();
    let db_key = key_of("key-file-path");
    let mut args: serde_json::Value = serde_json::from_str(&new_db_args(&db_key)).unwrap();
    args["key_file_name"] = serde_json::json!("/data/user/0/app/files/key.keyx");

    let refused = run_with_bytes("create_and_write_to_writer", &args.to_string(), None);

    assert!(
        refused.envelope.starts_with(r#"{"err":"#),
        "a path would mean a key file the database does not have: {}",
        refused.envelope
    );
}

#[test]
fn a_password_over_the_limit_is_refused_on_creating() {
    prepare();
    let db_key = key_of("password-too-long");
    let mut args: serde_json::Value = serde_json::from_str(&new_db_args(&db_key)).unwrap();
    args["password"] = serde_json::json!("a".repeat(257));

    let refused = run_with_bytes("create_and_write_to_writer", &args.to_string(), None);

    assert!(
        refused.envelope.contains(r#""kind":"PasswordTooLong""#),
        "{}",
        refused.envelope
    );
}
