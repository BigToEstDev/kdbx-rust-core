//! The recycle bin across the boundary (pass-docs, Step 69): only entries go there.
//!
//! What the core decides - the flag, the flat bin, all or nothing - is tested in the core; here the point is
//! that the lists of uuids reach it, every answer keeps the shape the contract files pin for Kotlin, and the
//! flag travels inside the settings both ways.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{close_database, key_of, ok_payload, open_database, set_form_field};

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

fn new_entry(db_key: &str, title: &str) -> String {
    let root = root_uuid(db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", title);
    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );

    form["uuid"]
        .as_str()
        .expect("a form has a uuid")
        .to_string()
}

fn delete(db_key: &str, entry_uuid: &str) {
    call_ok(
        "delete_entry",
        json!({"db_key": db_key, "entry_uuid": entry_uuid}),
    );
}

fn trash_titles(db_key: &str) -> Vec<String> {
    let mut titles: Vec<String> = call_ok("trash_entries", json!({ "db_key": db_key }))
        .as_array()
        .expect("a list")
        .iter()
        .map(|t| t["entry"]["title"].as_str().unwrap_or_default().to_string())
        .collect();
    titles.sort();
    titles
}

#[test]
fn the_trash_lists_deleted_entries_with_their_previous_group() {
    let db_key = key_of("trash-list");
    open_database(&db_key);

    let doomed = new_entry(&db_key, "Doomed");
    new_entry(&db_key, "Kept");
    delete(&db_key, &doomed);

    let envelope = call("trash_entries", json!({ "db_key": db_key }));
    assert_shape("trash_entries", &envelope);

    let item = &ok_payload(&envelope)[0];
    assert_eq!(item["entry"]["uuid"], doomed);
    assert_eq!(
        item["previous_group_uuid"].as_str(),
        Some(root_uuid(&db_key).as_str()),
        "the group it was deleted from lives on: {}",
        item
    );

    close_database(&db_key);
}

#[test]
fn the_trash_search_answers_with_the_term() {
    let db_key = key_of("trash-search");
    open_database(&db_key);

    let doomed = new_entry(&db_key, "Bank doomed");
    new_entry(&db_key, "Bank kept");
    delete(&db_key, &doomed);

    let envelope = call("search_trash", json!({"db_key": db_key, "term": "bank"}));
    assert_shape("search_trash", &envelope);

    let found = ok_payload(&envelope);
    assert_eq!(found["term"], "bank");
    let items = found["entry_items"].as_array().expect("a list");
    assert_eq!(items.len(), 1, "only the bin is looked into: {}", found);
    assert_eq!(items[0]["entry"]["uuid"], doomed);

    close_database(&db_key);
}

#[test]
fn picked_entries_are_restored_to_a_group_or_removed_for_good() {
    let db_key = key_of("trash-restore-remove");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let back = new_entry(&db_key, "Back");
    let gone = new_entry(&db_key, "Gone");
    let left = new_entry(&db_key, "Left");
    for entry in [&back, &gone, &left] {
        delete(&db_key, entry);
    }

    let restored = call(
        "restore_entries",
        json!({"db_key": db_key, "entry_uuids": [back], "group_uuid": root}),
    );
    assert_shape("restore_entries", &restored);
    let back_form = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": back}),
    );
    assert_eq!(back_form["group_uuid"].as_str(), Some(root.as_str()));

    let removed = call(
        "remove_entries_permanently",
        json!({"db_key": db_key, "entry_uuids": [gone]}),
    );
    assert_shape("remove_entries_permanently", &removed);

    assert_eq!(trash_titles(&db_key), vec!["Left".to_string()]);

    close_database(&db_key);
}

#[test]
fn a_restore_to_the_bin_itself_is_refused() {
    let db_key = key_of("trash-restore-refused");
    open_database(&db_key);

    let doomed = new_entry(&db_key, "Doomed");
    delete(&db_key, &doomed);
    let bin = call_ok("groups_summary_data", json!({ "db_key": db_key }))["recycle_bin_uuid"]
        .as_str()
        .expect("deleting creates the bin")
        .to_string();

    let envelope = call(
        "restore_entries",
        json!({"db_key": db_key, "entry_uuids": [doomed], "group_uuid": bin}),
    );
    assert!(envelope.starts_with(r#"{"err":"#), "{}", envelope);
    assert_eq!(trash_titles(&db_key), vec!["Doomed".to_string()]);

    close_database(&db_key);
}

#[test]
fn emptying_the_bin_takes_what_is_in_it_and_leaves_the_rest() {
    let db_key = key_of("trash-empty");
    open_database(&db_key);

    let doomed = new_entry(&db_key, "Doomed");
    new_entry(&db_key, "Kept");
    delete(&db_key, &doomed);

    let emptied = call("empty_trash", json!({ "db_key": db_key }));
    assert_shape("empty_trash", &emptied);

    assert!(trash_titles(&db_key).is_empty(), "the bin is empty");
    let all = call_ok(
        "entry_summary_data",
        json!({"db_key": db_key, "category": {"kind": "all_entries"}}),
    );
    assert_eq!(
        all.as_array().expect("a list").len(),
        1,
        "and what was not in it is still there"
    );

    close_database(&db_key);
}

// The flag travels in the settings: switched off, a delete is for good and the bin is gone
#[test]
fn with_the_bin_switched_off_a_delete_is_for_good() {
    let db_key = key_of("trash-switched-off");
    open_database(&db_key);

    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(settings["meta"]["recycle_bin_enabled"], true);
    settings["meta"]["recycle_bin_enabled"] = json!(false);
    call_ok(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );

    let doomed = new_entry(&db_key, "Doomed");
    delete(&db_key, &doomed);

    let gone = call(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": doomed}),
    );
    assert!(gone.starts_with(r#"{"err":"#), "{}", gone);
    assert!(trash_titles(&db_key).is_empty());

    close_database(&db_key);
}
