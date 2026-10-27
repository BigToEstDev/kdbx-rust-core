//! Checksums and merge across the boundary.
//!
//! These commands carry the bytes of the file on disk, and the tests give them exactly what SAF would:
//! the bytes a save produced. "Someone else wrote the file" is played by a second database opened
//! under another key - that is what a file changed elsewhere looks like from here.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    close_database, db_key_args, key_of, new_db_args, ok_payload, open_database, prepare,
    read_args, set_form_field,
};

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

/// The bytes of the database as a save produces them - what Kotlin would then write through SAF.
fn save_bytes(db_key: &str) -> Vec<u8> {
    let saved = run_with_bytes("save_kdbx_to_writer", &db_key_args(db_key), None);
    assert!(
        saved.envelope.starts_with(r#"{"ok":"#),
        "saving failed: {}",
        saved.envelope
    );

    saved.payload.expect("saving produces the file")
}

fn with_bytes(command: &str, args: Value, bytes: Vec<u8>) -> String {
    run_with_bytes(command, &args.to_string(), Some(bytes)).envelope
}

fn root_uuid(db_key: &str) -> String {
    call_ok("groups_summary_data", json!({ "db_key": db_key }))["root_uuid"]
        .as_str()
        .expect("the tree has to name its root")
        .to_string()
}

fn new_entry(db_key: &str, title: &str) {
    let root = root_uuid(db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", title);

    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );
}

#[test]
fn the_file_this_app_wrote_still_matches_and_a_different_one_does_not() {
    let db_key = key_of("checksum-verify");
    open_database(&db_key);

    // The save sets no checksum by itself - the app does that over the bytes it just wrote
    let bytes = save_bytes(&db_key);
    let set = with_bytes(
        "calculate_and_set_db_file_checksum",
        json!({ "db_key": db_key }),
        bytes.clone(),
    );
    assert_shape("calculate_and_set_db_file_checksum", &set);

    let verified = with_bytes(
        "verify_db_file_checksum",
        json!({ "db_key": db_key }),
        bytes.clone(),
    );
    assert_shape("verify_db_file_checksum", &verified);

    // A byte changed anywhere in the file is a file someone else wrote
    let mut tampered = bytes;
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;

    let refused = with_bytes(
        "verify_db_file_checksum",
        json!({ "db_key": db_key }),
        tampered,
    );
    assert!(
        refused.contains("DbFileContentChangeDetected"),
        "a changed file has its own kind, the ui answers it with the merge dialog: {}",
        refused
    );

    close_database(&db_key);
}

#[test]
fn the_checksum_the_core_holds_can_be_asked_for_without_the_file() {
    let db_key = key_of("checksum-hash");
    open_database(&db_key);

    let bytes = save_bytes(&db_key);
    call_ok_with_bytes("calculate_and_set_db_file_checksum", &db_key, bytes);

    let envelope = call("db_checksum_hash", json!({ "db_key": db_key }));
    assert_shape("db_checksum_hash", &envelope);

    let checksum = ok_payload(&envelope);
    assert!(
        !checksum["checksum"]
            .as_array()
            .expect("the checksum is a list of bytes")
            .is_empty(),
        "{}",
        checksum
    );

    close_database(&db_key);
}

#[test]
fn a_command_that_needs_the_file_refuses_to_work_without_it() {
    let db_key = key_of("checksum-no-bytes");
    open_database(&db_key);

    let envelope = call("verify_db_file_checksum", json!({ "db_key": db_key }));

    assert!(
        envelope.contains(r#""kind":"InvalidArguments""#),
        "the checksum is over the file, so the file has to come: {}",
        envelope
    );

    close_database(&db_key);
}

#[test]
fn a_file_written_elsewhere_is_merged_back_in() {
    prepare();
    let db_key = key_of("merge-target");

    // One database, saved - this stands in for the file as it was
    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);
    assert!(
        created.envelope.starts_with(r#"{"ok":"#),
        "{}",
        created.envelope
    );
    let original = created
        .payload
        .expect("the new database comes back as bytes");

    // "Somebody else" opens that same file under a key of its own and adds an entry
    let other_key = key_of("merge-source");
    let opened = run_with_bytes(
        "read_kdbx",
        &read_args(&other_key, "open sesame"),
        Some(original),
    );
    assert!(
        opened.envelope.starts_with(r#"{"ok":"#),
        "{}",
        opened.envelope
    );
    new_entry(&other_key, "Added elsewhere");
    let changed_file = save_bytes(&other_key);
    close_database(&other_key);

    // Back in our database, the file no longer matches
    let mismatch = with_bytes(
        "verify_db_file_checksum",
        json!({ "db_key": db_key }),
        changed_file.clone(),
    );
    assert!(
        mismatch.contains("DbFileContentChangeDetected"),
        "{}",
        mismatch
    );

    let envelope = with_bytes(
        "merge_kdbx_with_reader",
        json!({ "db_key": db_key }),
        changed_file,
    );
    assert_shape("merge_kdbx_with_reader", &envelope);

    let result = ok_payload(&envelope);
    assert_eq!(
        result["merge_done"].as_bool(),
        Some(true),
        "something was merged: {}",
        result
    );
    assert_eq!(
        result["different_databases"].as_bool(),
        Some(false),
        "the same database, edited elsewhere: {}",
        result
    );

    // And the entry added elsewhere is here now
    let titles: Vec<String> = call_ok(
        "entry_summary_data",
        json!({"db_key": db_key, "category": {"kind": "all_entries"}}),
    )
    .as_array()
    .expect("a list")
    .iter()
    .filter_map(|entry| entry["title"].as_str().map(str::to_string))
    .collect();
    assert_eq!(titles, vec!["Added elsewhere".to_string()]);

    close_database(&db_key);
}

#[test]
fn a_file_re_encrypted_elsewhere_cannot_be_merged() {
    prepare();
    let db_key = key_of("merge-other-password");

    run_with_bytes("create_and_write_to_writer", &new_db_args(&db_key), None);

    // A database of its own, with another password - what a file re-encrypted elsewhere looks like
    let stranger_key = key_of("merge-stranger");
    let stranger = run_with_bytes(
        "create_and_write_to_writer",
        &new_db_args(&stranger_key).replace("open sesame", "another password"),
        None,
    );
    let stranger_bytes = stranger.payload.expect("the database comes back as bytes");
    close_database(&stranger_key);

    let envelope = with_bytes(
        "merge_kdbx_with_reader",
        json!({ "db_key": db_key }),
        stranger_bytes,
    );

    assert!(
        envelope.contains("MergeFailedCredentialsChanged"),
        "the kind has to say that the credentials differ, so the ui can offer saving a copy: {}",
        envelope
    );

    close_database(&db_key);
}

fn call_ok_with_bytes(command: &str, db_key: &str, bytes: Vec<u8>) {
    let envelope = with_bytes(command, json!({ "db_key": db_key }), bytes);
    assert!(
        envelope.starts_with(r#"{"ok":"#),
        "{} failed: {}",
        command,
        envelope
    );
}
