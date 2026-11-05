//! The attachments of entries across the boundary (pass-docs, Step 102): new ones come with the form - names and
//! sizes in `new_attachments`, the bytes one after another in the slot - and the rest travel in the form.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    close_database, db_key_args, key_of, ok_payload, open_database, read_args, set_form_field,
    TEST_PASSWORD,
};

fn call(command: &str, args: Value, bytes: Option<Vec<u8>>) -> String {
    run_with_bytes(command, &args.to_string(), bytes).envelope
}

fn call_ok(command: &str, args: Value) -> Value {
    let envelope = call(command, args, None);
    assert!(
        envelope.starts_with(r#"{"ok":"#),
        "{} failed: {}",
        command,
        envelope
    );
    ok_payload(&envelope)
}

fn blank_form(db_key: &str, title: &str) -> Value {
    let root = call_ok("groups_summary_data", json!({ "db_key": db_key }))["root_uuid"].clone();
    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", title);
    form
}

fn form_of(db_key: &str, entry_uuid: &Value) -> Value {
    call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": entry_uuid}),
    )
}

/// The arguments of a form save with new attachments, and the bytes of the slot.
fn with_files(db_key: &str, form: &Value, files: &[(&str, &[u8])]) -> (Value, Option<Vec<u8>>) {
    let list: Vec<Value> = files
        .iter()
        .map(|(name, data)| json!({"name": name, "size": data.len()}))
        .collect();
    let bytes: Vec<u8> = files.iter().flat_map(|(_, data)| data.to_vec()).collect();
    (
        json!({"db_key": db_key, "form_data": form, "new_attachments": list}),
        Some(bytes),
    )
}

/// The attachments of a form as the ui lists them: name and size.
fn listed(form: &Value) -> Vec<(String, u64)> {
    form["binary_key_values"]
        .as_array()
        .expect("a form lists its attachments")
        .iter()
        .map(|b| {
            (
                b["key"].as_str().unwrap().to_string(),
                b["data_size"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn kind_of(envelope: &str) -> String {
    let parsed: Value = serde_json::from_str(envelope).expect("the envelope is not json");
    parsed["err"]["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("not a refusal: {}", envelope))
        .to_string()
}

#[test]
fn new_attachments_come_with_the_form_and_survive_the_file() {
    let db_key = key_of("attachments-insert");
    open_database(&db_key);
    let form = blank_form(&db_key, "With files");
    let uuid = form["uuid"].clone();

    let (args, bytes) = with_files(
        &db_key,
        &form,
        &[("a.txt", b"first"), ("b.bin", &[0, 1, 255])],
    );
    let inserted = call("insert_entry_from_form_data", args, bytes);
    assert_shape("insert_entry_from_form_data", &inserted);
    let expected = vec![("a.txt".to_string(), 5), ("b.bin".to_string(), 3)];
    assert_eq!(listed(&form_of(&db_key, &uuid)), expected);

    // Through the bytes of the file, as the app saves and opens it
    let saved = run_with_bytes("save_kdbx_to_writer", &db_key_args(&db_key), None);
    let file = saved.payload.expect("a save hands the file back");
    close_database(&db_key);
    let read = run_with_bytes("read_kdbx", &read_args(&db_key, TEST_PASSWORD), Some(file));
    assert!(read.envelope.starts_with(r#"{"ok":"#), "{}", read.envelope);
    assert_eq!(listed(&form_of(&db_key, &uuid)), expected);

    close_database(&db_key);
}

#[test]
fn new_attachments_join_those_the_form_has() {
    let db_key = key_of("attachments-update");
    open_database(&db_key);
    let form = blank_form(&db_key, "Edited");
    let uuid = form["uuid"].clone();
    let (args, bytes) = with_files(&db_key, &form, &[("a.txt", b"first")]);
    call("insert_entry_from_form_data", args, bytes);

    let (args, bytes) = with_files(&db_key, &form_of(&db_key, &uuid), &[("b.txt", b"second")]);
    let updated = call("update_entry_from_form_data", args, bytes);
    assert_shape("update_entry_from_form_data", &updated);

    assert_eq!(
        listed(&form_of(&db_key, &uuid)),
        vec![("a.txt".to_string(), 5), ("b.txt".to_string(), 6)]
    );
    close_database(&db_key);
}

#[test]
fn a_form_with_no_new_attachments_takes_no_bytes() {
    let db_key = key_of("attachments-no-list");
    open_database(&db_key);
    let form = blank_form(&db_key, "No list");

    let refused = call(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
        Some(b"stray".to_vec()),
    );

    assert_eq!(kind_of(&refused), "InvalidArguments");
    assert!(form_of_missing(&db_key, &form["uuid"]));
    close_database(&db_key);
}

#[test]
fn new_attachments_with_no_bytes_are_refused() {
    let db_key = key_of("attachments-no-bytes");
    open_database(&db_key);
    let form = blank_form(&db_key, "No bytes");
    let (args, _) = with_files(&db_key, &form, &[("a.txt", b"first")]);

    let refused = call("insert_entry_from_form_data", args, None);

    assert_eq!(kind_of(&refused), "InvalidArguments");
    assert!(form_of_missing(&db_key, &form["uuid"]));
    close_database(&db_key);
}

#[test]
fn sizes_that_do_not_cover_the_bytes_are_refused_by_the_core() {
    let db_key = key_of("attachments-sizes");
    open_database(&db_key);
    let form = blank_form(&db_key, "Sizes");
    let (args, _) = with_files(&db_key, &form, &[("a.txt", b"first")]);

    let refused = call("insert_entry_from_form_data", args, Some(b"firs".to_vec()));

    assert_eq!(kind_of(&refused), "DataError");
    assert!(form_of_missing(&db_key, &form["uuid"]));
    close_database(&db_key);
}

#[test]
fn a_repeated_name_is_refused_by_the_core() {
    let db_key = key_of("attachments-names");
    open_database(&db_key);
    let form = blank_form(&db_key, "Names");
    let uuid = form["uuid"].clone();
    let (args, bytes) = with_files(&db_key, &form, &[("a.txt", b"one")]);
    call("insert_entry_from_form_data", args, bytes);

    let (args, bytes) = with_files(&db_key, &form_of(&db_key, &uuid), &[("a.txt", b"two")]);
    let refused = call("update_entry_from_form_data", args, bytes);

    assert_eq!(kind_of(&refused), "DataError");
    assert_eq!(
        listed(&form_of(&db_key, &uuid)),
        vec![("a.txt".to_string(), 3)]
    );
    close_database(&db_key);
}

fn form_of_missing(db_key: &str, entry_uuid: &Value) -> bool {
    let envelope = call(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": entry_uuid}),
        None,
    );
    !envelope.starts_with(r#"{"ok":"#)
}
