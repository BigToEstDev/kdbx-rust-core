//! A copy merged and a different database imported, across the boundary (Step 106).
//!
//! The other file is played the way it reaches the app: bytes a save produced. "A copy" is the same file
//! opened under a key of its own and changed there - on another device, maybe with another password. "A
//! different database" is one created on its own: a root group of its own. Both ways (Step 109) - the bytes of
//! the copy's file come back beside the result, encrypted for that file.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    close_database, db_key_args, key_of, new_db_args, ok_payload, prepare, read_args,
    set_form_field, TEST_PASSWORD,
};

const OTHER_PASSWORD: &str = "another password";

fn call(command: &str, args: Value) -> String {
    run_with_bytes(command, &args.to_string(), None).envelope
}

fn call_ok(command: &str, args: Value) -> Value {
    let envelope = call(command, args);
    assert!(
        envelope.starts_with(r#"{"ok":"#),
        "{} failed: {}",
        command,
        envelope
    );

    ok_payload(&envelope)
}

/// A new database, open under the key its `args` name, and the bytes of its file.
fn create(args: String) -> Vec<u8> {
    prepare();
    let created = run_with_bytes("create_and_write_to_writer", &args, None);
    assert!(
        created.envelope.starts_with(r#"{"ok":"#),
        "{}",
        created.envelope
    );

    created
        .payload
        .expect("the new database comes back as bytes")
}

fn save_bytes(db_key: &str) -> Vec<u8> {
    let saved = run_with_bytes("save_kdbx_to_writer", &db_key_args(db_key), None);
    assert!(
        saved.envelope.starts_with(r#"{"ok":"#),
        "saving failed: {}",
        saved.envelope
    );

    saved.payload.expect("saving produces the file")
}

fn new_entry(db_key: &str, title: &str) {
    let root = call_ok("groups_summary_data", json!({ "db_key": db_key }))["root_uuid"]
        .as_str()
        .expect("the tree names its root")
        .to_string();

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", title);

    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );
}

fn titles(db_key: &str) -> Vec<String> {
    let mut titles: Vec<String> = call_ok(
        "entry_summary_data",
        json!({"db_key": db_key, "category": {"kind": "all_entries"}}),
    )
    .as_array()
    .expect("a list")
    .iter()
    .filter_map(|entry| entry["title"].as_str().map(str::to_string))
    .collect();
    titles.sort();
    titles
}

fn set_password(db_key: &str, password: &str) {
    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    settings["password"] = json!(password);
    settings["password_used"] = json!(true);
    settings["password_changed"] = json!(true);
    call_ok(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );
}

/// The file of `original` changed elsewhere: opened under a key of its own, an entry added, saved - and,
/// when `password` is given, re-encrypted with it first.
fn changed_copy(copy_key: &str, original: Vec<u8>, title: &str, password: Option<&str>) -> Vec<u8> {
    let opened = run_with_bytes(
        "read_kdbx",
        &read_args(copy_key, TEST_PASSWORD),
        Some(original),
    );
    assert!(
        opened.envelope.starts_with(r#"{"ok":"#),
        "{}",
        opened.envelope
    );
    if let Some(password) = password {
        set_password(copy_key, password);
    }
    new_entry(copy_key, title);
    let bytes = save_bytes(copy_key);
    close_database(copy_key);
    bytes
}

fn key_file_json(content: &[u8]) -> Value {
    json!({ "name": "other.keyx", "content": crate::key_file::encode(content) })
}

fn new_key_file() -> Vec<u8> {
    run_with_bytes("generate_key_file", "", None)
        .payload
        .expect("a generated key file")
}

fn merge_args(db_key: &str, password: Option<&str>, key_file: Option<Value>) -> Value {
    let mut args = json!({ "db_key": db_key, "password": password });
    if let Some(key_file) = key_file {
        args["key_file"] = key_file;
    }
    args
}

fn with_bytes(command: &str, args: Value, bytes: Vec<u8>) -> String {
    run_with_bytes(command, &args.to_string(), Some(bytes)).envelope
}

fn checksum(db_key: &str) -> Value {
    call_ok("db_checksum_hash", json!({ "db_key": db_key }))["checksum"].clone()
}

#[test]
fn a_copy_with_another_password_is_merged_with_that_password() {
    let db_key = key_of("merge-copy-target");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("merge-copy-source"),
        original,
        "Added on the phone",
        Some(OTHER_PASSWORD),
    );

    let envelope = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(OTHER_PASSWORD), None),
        copy,
    );
    assert_shape("merge_kdbx_from_bytes", &envelope);

    let result = ok_payload(&envelope);
    assert_eq!(result["merge_done"].as_bool(), Some(true), "{}", result);
    assert_eq!(
        result["different_databases"].as_bool(),
        Some(false),
        "{}",
        result
    );
    assert_eq!(titles(&db_key), vec!["Added on the phone".to_string()]);

    close_database(&db_key);
}

#[test]
fn a_copy_is_not_merged_with_a_wrong_password() {
    let db_key = key_of("merge-copy-wrong-password");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("merge-copy-wrong-password-source"),
        original,
        "Added on the phone",
        Some(OTHER_PASSWORD),
    );

    // The password of the open database is not the copy's any more
    let refused = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        copy,
    );
    assert!(
        refused.contains(r#""kind":"InvalidCredentials""#),
        "{}",
        refused
    );
    assert!(titles(&db_key).is_empty(), "nothing came in");

    close_database(&db_key);
}

#[test]
fn a_different_database_is_not_merged_as_a_copy() {
    let db_key = key_of("merge-not-a-copy");
    create(new_db_args(&db_key));
    new_entry(&db_key, "Mine");

    let stranger_key = key_of("merge-not-a-copy-stranger");
    create(new_db_args(&stranger_key));
    new_entry(&stranger_key, "Theirs");
    let stranger = save_bytes(&stranger_key);
    close_database(&stranger_key);

    let refused = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        stranger,
    );
    assert!(
        refused.contains(r#""kind":"NotSameDatabase""#),
        "{}",
        refused
    );
    assert_eq!(titles(&db_key), vec!["Mine".to_string()], "nothing changed");

    close_database(&db_key);
}

#[test]
fn a_different_database_with_a_password_and_a_key_file_is_imported() {
    let db_key = key_of("import-target");
    create(new_db_args(&db_key));
    new_entry(&db_key, "Mine");

    let key_file = new_key_file();
    let stranger_key = key_of("import-stranger");
    let mut args: Value = serde_json::from_str(&new_db_args(&stranger_key)).unwrap();
    args["password"] = json!(OTHER_PASSWORD);
    args["key_file"] = key_file_json(&key_file);
    create(args.to_string());
    new_entry(&stranger_key, "Theirs");
    let stranger = save_bytes(&stranger_key);
    close_database(&stranger_key);

    let envelope = with_bytes(
        "import_kdbx_from_bytes",
        merge_args(
            &db_key,
            Some(OTHER_PASSWORD),
            Some(key_file_json(&key_file)),
        ),
        stranger,
    );
    assert_shape("import_kdbx_from_bytes", &envelope);

    let result = ok_payload(&envelope);
    assert_eq!(
        result["different_databases"].as_bool(),
        Some(true),
        "{}",
        result
    );
    assert_eq!(
        titles(&db_key),
        vec!["Mine".to_string(), "Theirs".to_string()]
    );

    close_database(&db_key);
}

#[test]
fn a_different_database_with_only_a_key_file_is_imported() {
    let db_key = key_of("import-key-file-only");
    create(new_db_args(&db_key));

    let key_file = new_key_file();
    let stranger_key = key_of("import-key-file-only-stranger");
    let mut args: Value = serde_json::from_str(&new_db_args(&stranger_key)).unwrap();
    args["password"] = Value::Null;
    args["key_file"] = key_file_json(&key_file);
    create(args.to_string());
    new_entry(&stranger_key, "Theirs");
    let stranger = save_bytes(&stranger_key);
    close_database(&stranger_key);

    // Without its key file it does not open
    let refused = with_bytes(
        "import_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        stranger.clone(),
    );
    assert!(
        refused.contains(r#""kind":"InvalidCredentials""#),
        "{}",
        refused
    );

    let envelope = with_bytes(
        "import_kdbx_from_bytes",
        merge_args(&db_key, None, Some(key_file_json(&key_file))),
        stranger,
    );
    assert!(envelope.starts_with(r#"{"ok":"#), "{}", envelope);
    assert_eq!(titles(&db_key), vec!["Theirs".to_string()]);

    close_database(&db_key);
}

#[test]
fn a_copy_is_not_imported_as_a_different_database() {
    let db_key = key_of("import-a-copy");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("import-a-copy-source"),
        original,
        "Added on the phone",
        None,
    );

    let refused = with_bytes(
        "import_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        copy,
    );
    assert!(refused.contains(r#""kind":"SameDatabase""#), "{}", refused);
    assert!(titles(&db_key).is_empty(), "nothing came in");

    close_database(&db_key);
}

#[test]
fn the_checksum_of_the_open_file_stays_after_a_merge() {
    let db_key = key_of("merge-keeps-checksum");
    let original = create(new_db_args(&db_key));
    let before = checksum(&db_key);
    let copy = changed_copy(
        &key_of("merge-keeps-checksum-source"),
        original,
        "Added on the phone",
        None,
    );

    let envelope = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        copy,
    );
    assert!(envelope.starts_with(r#"{"ok":"#), "{}", envelope);

    // The bytes were another file: the next save still compares against this one
    assert_eq!(checksum(&db_key), before);

    close_database(&db_key);
}

#[test]
fn the_merged_entries_are_in_the_file_after_saving_and_reading_it_again() {
    let db_key = key_of("merge-saved");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("merge-saved-source"),
        original,
        "Added on the phone",
        Some(OTHER_PASSWORD),
    );

    let envelope = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(OTHER_PASSWORD), None),
        copy,
    );
    assert!(envelope.starts_with(r#"{"ok":"#), "{}", envelope);

    let saved = save_bytes(&db_key);
    close_database(&db_key);

    // Still the password of the open database, not the copy's
    let read = run_with_bytes("read_kdbx", &read_args(&db_key, TEST_PASSWORD), Some(saved));
    assert!(read.envelope.starts_with(r#"{"ok":"#), "{}", read.envelope);
    assert_eq!(titles(&db_key), vec!["Added on the phone".to_string()]);

    close_database(&db_key);
}

#[test]
fn the_other_database_is_not_left_open() {
    let db_key = key_of("merge-leaves-nothing");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("merge-leaves-nothing-source"),
        original,
        "Added on the phone",
        None,
    );

    let envelope = with_bytes(
        "merge_kdbx_from_bytes",
        merge_args(&db_key, Some(TEST_PASSWORD), None),
        copy,
    );
    assert!(envelope.starts_with(r#"{"ok":"#), "{}", envelope);

    let opened = call_ok("is_db_opened", json!({ "db_key": "" }));
    assert_eq!(
        opened["opened"].as_bool(),
        Some(false),
        "the other file has no place in the store"
    );
    assert!(
        kdbx_rust_core::db_service::KeyStoreOperation::get_key("").is_none(),
        "nor its keys in the key store"
    );

    close_database(&db_key);
}

#[test]
fn a_locked_database_takes_no_merge() {
    let db_key = key_of("merge-locked");
    let original = create(new_db_args(&db_key));
    let copy = changed_copy(
        &key_of("merge-locked-source"),
        original,
        "Added on the phone",
        None,
    );
    call_ok("lock_kdbx", json!({ "db_key": db_key }));

    for command in [
        "merge_kdbx_from_bytes",
        "import_kdbx_from_bytes",
        "merge_kdbx_both_ways",
    ] {
        let refused = with_bytes(
            command,
            merge_args(&db_key, Some(TEST_PASSWORD), None),
            copy.clone(),
        );
        assert!(refused.contains(r#""kind":"DbLocked""#), "{}", refused);
    }

    close_database(&db_key);
}

#[test]
fn a_database_that_is_not_open_takes_no_merge() {
    prepare();
    let stranger_key = key_of("merge-not-open-stranger");
    let stranger = create(new_db_args(&stranger_key));
    close_database(&stranger_key);

    for command in [
        "merge_kdbx_from_bytes",
        "import_kdbx_from_bytes",
        "merge_kdbx_both_ways",
    ] {
        let refused = with_bytes(
            command,
            merge_args(&key_of("merge-not-open"), Some(TEST_PASSWORD), None),
            stranger.clone(),
        );
        assert!(refused.contains(r#""kind":"DbKeyNotFound""#), "{}", refused);
    }
}

#[test]
fn a_merge_needs_the_bytes_of_the_other_file() {
    prepare();
    for command in [
        "merge_kdbx_from_bytes",
        "import_kdbx_from_bytes",
        "merge_kdbx_both_ways",
    ] {
        let refused = call(command, merge_args(&key_of("merge-no-bytes"), None, None));
        assert!(refused.starts_with(r#"{"err":"#), "{}", refused);
    }
}

// --- Both ways (Step 109) ---

#[test]
fn both_ways_the_bytes_of_the_copy_open_with_its_own_password_and_hold_both_sides() {
    let db_key = key_of("both-ways-target");
    let original = create(new_db_args(&db_key));
    new_entry(&db_key, "Added here");
    let copy = changed_copy(
        &key_of("both-ways-source"),
        original,
        "Added on the phone",
        Some(OTHER_PASSWORD),
    );

    let answer = run_with_bytes(
        "merge_kdbx_both_ways",
        &merge_args(&db_key, Some(OTHER_PASSWORD), None).to_string(),
        Some(copy),
    );
    assert_shape("merge_kdbx_both_ways", &answer.envelope);
    let result = ok_payload(&answer.envelope);
    assert_eq!(result["merge_done"].as_bool(), Some(true), "{}", result);
    let both = vec!["Added here".to_string(), "Added on the phone".to_string()];
    assert_eq!(titles(&db_key), both);
    let bytes = answer.payload.expect("the bytes of the copy's file");

    // Not with the password of the open database - the copy keeps its own
    let reopened_key = key_of("both-ways-reopened");
    let refused = run_with_bytes(
        "read_kdbx",
        &read_args(&reopened_key, TEST_PASSWORD),
        Some(bytes.clone()),
    );
    assert!(
        refused.envelope.contains(r#""kind":"InvalidCredentials""#),
        "{}",
        refused.envelope
    );
    let opened = run_with_bytes(
        "read_kdbx",
        &read_args(&reopened_key, OTHER_PASSWORD),
        Some(bytes),
    );
    assert!(
        opened.envelope.starts_with(r#"{"ok":"#),
        "{}",
        opened.envelope
    );
    assert_eq!(titles(&reopened_key), both);

    close_database(&reopened_key);
    close_database(&db_key);
}

#[test]
fn both_ways_keeps_the_checksum_of_the_open_file() {
    let db_key = key_of("both-ways-checksum");
    let original = create(new_db_args(&db_key));
    let before = checksum(&db_key);
    let copy = changed_copy(
        &key_of("both-ways-checksum-source"),
        original,
        "Added on the phone",
        None,
    );

    let answer = run_with_bytes(
        "merge_kdbx_both_ways",
        &merge_args(&db_key, Some(TEST_PASSWORD), None).to_string(),
        Some(copy),
    );
    assert!(answer.payload.is_some(), "{}", answer.envelope);
    assert_eq!(checksum(&db_key), before, "the bytes are for another file");

    close_database(&db_key);
}

#[test]
fn both_ways_refuses_a_different_database_and_gives_no_bytes() {
    let db_key = key_of("both-ways-not-a-copy");
    create(new_db_args(&db_key));
    new_entry(&db_key, "Mine");

    let stranger_key = key_of("both-ways-not-a-copy-stranger");
    create(new_db_args(&stranger_key));
    new_entry(&stranger_key, "Theirs");
    let stranger = save_bytes(&stranger_key);
    close_database(&stranger_key);

    let refused = run_with_bytes(
        "merge_kdbx_both_ways",
        &merge_args(&db_key, Some(TEST_PASSWORD), None).to_string(),
        Some(stranger),
    );
    assert!(
        refused.envelope.contains(r#""kind":"NotSameDatabase""#),
        "{}",
        refused.envelope
    );
    assert!(refused.payload.is_none(), "no bytes for a refused merge");
    assert_eq!(titles(&db_key), vec!["Mine".to_string()], "nothing changed");

    close_database(&db_key);
}
