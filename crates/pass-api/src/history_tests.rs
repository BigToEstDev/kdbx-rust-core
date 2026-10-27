//! The history of an entry across the boundary.
//!
//! History is not created by a command of its own: the core writes a version every time an entry is
//! updated. So these tests edit an entry twice and then look at what the history says - which is also
//! the only way the app will ever produce one.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    close_database, form_field, key_of, ok_payload, open_database, set_form_field,
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

fn root_uuid(db_key: &str) -> String {
    call_ok("groups_summary_data", json!({ "db_key": db_key }))["root_uuid"]
        .as_str()
        .expect("the tree has to name its root")
        .to_string()
}

/// An entry that has been saved `revisions` times after its creation, so it has that many old
/// versions behind it.
fn entry_with_history(db_key: &str, revisions: usize) -> String {
    let root = root_uuid(db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", "Version 0");
    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );

    let uuid = form["uuid"]
        .as_str()
        .expect("a form has a uuid")
        .to_string();

    for revision in 1..=revisions {
        let mut current = call_ok(
            "get_entry_form_data_by_id",
            json!({"db_key": db_key, "entry_uuid": uuid}),
        );
        set_form_field(&mut current, "Title", &format!("Version {}", revision));
        call_ok(
            "update_entry_from_form_data",
            json!({"db_key": db_key, "form_data": current}),
        );
    }

    uuid
}

#[test]
fn every_update_leaves_a_version_behind() {
    let db_key = key_of("history-summary");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 2);

    let envelope = call(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_shape("history_entries_summary", &envelope);

    let versions = ok_payload(&envelope);
    let summaries = versions.as_array().expect("the history is a list");
    assert_eq!(
        summaries.len(),
        2,
        "two updates leave two versions: {}",
        versions
    );
    assert!(
        summaries
            .iter()
            .all(|entry| entry["history_index"].is_number()),
        "a version is addressed by its index: {}",
        versions
    );

    close_database(&db_key);
}

#[test]
fn an_old_version_is_read_as_a_form() {
    let db_key = key_of("history-read");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 1);

    let envelope = call(
        "history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": 0}),
    );
    assert_shape("history_entry_by_index", &envelope);

    let old = ok_payload(&envelope);
    assert_eq!(
        form_field(&old, "Title"),
        Some("Version 0"),
        "the first version is the entry as it was created"
    );

    // And the entry itself is the current one, not the version
    let current = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_eq!(form_field(&current, "Title"), Some("Version 1"));

    close_database(&db_key);
}

#[test]
fn one_version_is_deleted_and_then_the_whole_history() {
    let db_key = key_of("history-delete");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 3);

    let deleted_one = call(
        "delete_history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": 0}),
    );
    assert_shape("delete_history_entry_by_index", &deleted_one);

    let after_one = call_ok(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_eq!(
        after_one.as_array().expect("a list").len(),
        2,
        "one version fewer: {}",
        after_one
    );

    let deleted_all = call(
        "delete_history_entries",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_shape("delete_history_entries", &deleted_all);

    let after_all = call_ok(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert!(
        after_all.as_array().expect("a list").is_empty(),
        "the history is gone: {}",
        after_all
    );

    // The entry itself survives losing its history
    let current = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_eq!(form_field(&current, "Title"), Some("Version 3"));

    close_database(&db_key);
}

#[test]
fn an_index_that_is_not_there_is_a_failure_and_not_a_panic() {
    let db_key = key_of("history-missing-index");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 1);

    let envelope = call(
        "history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": 42}),
    );

    assert!(
        envelope.starts_with(r#"{"err":"#),
        "an index past the end has to come back as a refusal: {}",
        envelope
    );
    assert!(envelope.contains("NotFound"), "{}", envelope);

    close_database(&db_key);
}

#[test]
fn the_history_of_an_entry_that_does_not_exist_says_so() {
    let db_key = key_of("history-missing-entry");
    open_database(&db_key);

    let envelope = call(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": "00000000-0000-4000-8000-000000000000"}),
    );

    assert!(envelope.contains("NotFound"), "{}", envelope);

    close_database(&db_key);
}

/// Asserts the call was refused with `NotFound` - and not answered `ok` with nothing deleted.
fn assert_not_found(envelope: &str) {
    assert!(
        envelope.starts_with(r#"{"err":"#),
        "nothing was deleted, so it has to come back as a refusal: {}",
        envelope
    );
    assert!(envelope.contains("NotFound"), "{}", envelope);
}

#[test]
fn deleting_a_version_that_is_not_there_is_refused_and_the_history_stays() {
    let db_key = key_of("history-delete-missing-index");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 2);

    let past_the_end = call(
        "delete_history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": 2}),
    );
    let negative = call(
        "delete_history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": -1}),
    );
    let left = call_ok(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );

    assert_not_found(&past_the_end);
    assert_not_found(&negative);
    assert_eq!(
        left.as_array().expect("a list").len(),
        2,
        "the history is as it was: {}",
        left
    );

    close_database(&db_key);
}

#[test]
fn deleting_the_history_of_an_entry_that_does_not_exist_is_refused() {
    let db_key = key_of("history-delete-missing-entry");
    open_database(&db_key);

    let stranger = "00000000-0000-4000-8000-000000000000";
    let one = call(
        "delete_history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": stranger, "index": 0}),
    );
    let all = call(
        "delete_history_entries",
        json!({"db_key": db_key, "entry_uuid": stranger}),
    );

    assert_not_found(&one);
    assert_not_found(&all);

    close_database(&db_key);
}

/// How the app brings a version back: the version as a form, sent back as the entry. It has to be the
/// entry again - same uuid, its group kept - with the state before it put into the history.
#[test]
fn a_version_sent_back_as_the_entry_is_the_entry_again_and_the_state_before_goes_into_the_history()
{
    let db_key = key_of("history-restore");
    open_database(&db_key);

    let uuid = entry_with_history(&db_key, 2);

    let version = call_ok(
        "history_entry_by_index",
        json!({"db_key": db_key, "entry_uuid": uuid, "index": 0}),
    );
    assert_eq!(
        version["uuid"].as_str(),
        Some(uuid.as_str()),
        "a version keeps the uuid of its entry"
    );
    call_ok(
        "update_entry_from_form_data",
        json!({"db_key": db_key, "form_data": version}),
    );

    let current = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    let versions = call_ok(
        "history_entries_summary",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    let titles: Vec<&str> = versions
        .as_array()
        .expect("a list")
        .iter()
        .map(|v| v["title"].as_str().unwrap_or_default())
        .collect();

    assert_eq!(form_field(&current, "Title"), Some("Version 0"));
    assert_eq!(
        titles,
        vec!["Version 0", "Version 1", "Version 2"],
        "the state before - Version 2 - is the newest version now"
    );

    close_database(&db_key);
}
