//! Search and tags across the boundary.

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

/// An entry with a title and, if given, tags on it.
fn new_entry(db_key: &str, title: &str, tags: &[&str]) {
    let root = root_uuid(db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", title);
    if !tags.is_empty() {
        form["tags"] = json!(tags);
    }

    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );
}

fn found_titles(result: &Value) -> Vec<String> {
    result["entry_items"]
        .as_array()
        .expect("a search result lists its entries")
        .iter()
        .filter_map(|entry| entry["title"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn a_term_finds_the_entries_that_carry_it_and_comes_back_with_them() {
    let db_key = key_of("search-term");
    open_database(&db_key);

    new_entry(&db_key, "Bank of the North", &[]);
    new_entry(&db_key, "Mail", &[]);

    let envelope = call("search_term", json!({"db_key": db_key, "term": "Bank"}));
    assert_shape("search_term", &envelope);

    let result = ok_payload(&envelope);
    assert_eq!(
        result["term"].as_str(),
        Some("Bank"),
        "the term comes back, so a screen can drop the answer to a search already typed past: {}",
        result
    );
    assert_eq!(found_titles(&result), vec!["Bank of the North".to_string()]);

    close_database(&db_key);
}

#[test]
fn a_password_is_not_what_a_term_finds() {
    let db_key = key_of("search-password");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", "Shop");
    set_form_field(&mut form, "Password", "hunter2");
    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );

    let result = call_ok("search_term", json!({"db_key": db_key, "term": "hunter2"}));
    assert!(found_titles(&result).is_empty(), "{}", result);

    close_database(&db_key);
}

#[test]
fn a_term_that_matches_nothing_is_an_empty_result_and_not_a_failure() {
    let db_key = key_of("search-nothing");
    open_database(&db_key);

    new_entry(&db_key, "Mail", &[]);

    let result = call_ok(
        "search_term",
        json!({"db_key": db_key, "term": "nothing here"}),
    );

    assert!(found_titles(&result).is_empty(), "{}", result);

    close_database(&db_key);
}

#[test]
fn the_tags_of_entries_and_groups_are_listed_apart() {
    let db_key = key_of("search-tags");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    new_entry(&db_key, "Tagged", &["work", "money"]);

    let mut group = call_ok(
        "new_blank_group_with_parent",
        json!({"parent_group_uuid": root, "mark_as_category": false}),
    );
    group["name"] = json!("Tagged group");
    group["tags"] = json!("travel");
    call_ok("insert_group", json!({"db_key": db_key, "group": group}));

    let envelope = call("collect_entry_group_tags", json!({ "db_key": db_key }));
    assert_shape("collect_entry_group_tags", &envelope);

    let tags = ok_payload(&envelope);
    let entry_tags = tags["entry_tags"]
        .as_array()
        .expect("entry tags are a list");
    let group_tags = tags["group_tags"]
        .as_array()
        .expect("group tags are a list");

    assert!(
        entry_tags.iter().any(|tag| tag == "work"),
        "the tags of an entry are there: {}",
        tags
    );
    assert!(
        group_tags.iter().any(|tag| tag == "travel"),
        "and the tags of a group are kept apart: {}",
        tags
    );

    close_database(&db_key);
}

#[test]
fn searching_a_database_that_is_not_open_says_so() {
    let envelope = call(
        "search_term",
        json!({"db_key": "content://test/never-opened-search.kdbx", "term": "x"}),
    );

    assert!(envelope.contains("DbKeyNotFound"), "{}", envelope);
}
