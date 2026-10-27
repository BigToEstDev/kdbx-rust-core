//! Groups across the boundary, on a real database held in memory.
//!
//! The point of these tests is not that the core can move a group - the core has its own tests for that -
//! but that the *boundary* carries it: the arguments parse, the uuids survive the round trip as strings,
//! a group edited from json is still the group the core accepts back, and every answer keeps the shape
//! the contract files pin for Kotlin.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{
    close_database, db_key_args, key_of, ok_payload, open_database, prepare,
};

/// Runs a command with a json object of arguments and returns the envelope.
fn call(command: &str, args: Value) -> String {
    run_with_bytes(command, &args.to_string(), None).envelope
}

/// The same, failing the test when the command did not succeed - for the steps a test only needs to
/// have happened.
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

/// The uuid of the root group of a freshly created database, which is where new groups go.
fn root_uuid(db_key: &str) -> String {
    let tree = call_ok("groups_summary_data", json!({ "db_key": db_key }));

    tree["root_uuid"]
        .as_str()
        .expect("the tree has to name its root")
        .to_string()
}

/// A group created under the root, answered as the core's own `Group`.
fn new_group(db_key: &str, name: &str, parent_uuid: &str) -> Value {
    let mut group = call_ok(
        "new_blank_group_with_parent",
        json!({"parent_group_uuid": parent_uuid, "mark_as_category": false}),
    );
    group["name"] = json!(name);

    // The whole group goes back in, the round trip the ui makes; its answer is pinned here because
    // every test that needs a group goes through this function
    let envelope = call("insert_group", json!({"db_key": db_key, "group": group}));
    assert!(
        envelope.starts_with(r#"{"ok":"#),
        "insert_group failed: {}",
        envelope
    );
    assert_shape("insert_group", &envelope);

    group
}

fn uuid_of(group: &Value) -> &str {
    group["uuid"].as_str().expect("a group has a uuid")
}

#[test]
fn the_tree_of_a_new_database_has_a_root_and_the_shape_kotlin_expects() {
    let db_key = key_of("group-tree");
    open_database(&db_key);

    let envelope = call("groups_summary_data", json!({ "db_key": db_key }));
    assert_shape("groups_summary_data", &envelope);

    let tree = ok_payload(&envelope);
    let root = tree["root_uuid"].as_str().expect("there has to be a root");
    assert!(
        tree["groups"].get(root).is_some(),
        "the root has to be among the groups of the tree: {}",
        tree
    );

    close_database(&db_key);
}

#[test]
fn a_group_is_created_read_back_and_renamed() {
    let db_key = key_of("group-round-trip");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    // The blank group carries the parent it was asked for, and a uuid of its own
    let blank_envelope = call(
        "new_blank_group_with_parent",
        json!({"parent_group_uuid": root, "mark_as_category": false}),
    );
    assert_shape("new_blank_group_with_parent", &blank_envelope);
    let blank = ok_payload(&blank_envelope);
    assert_eq!(blank["parent_group_uuid"].as_str(), Some(root.as_str()));

    let group = new_group(&db_key, "Work", &root);
    let uuid = uuid_of(&group).to_string();

    // Read it back: this is the json an edit screen would be filled from
    let read_envelope = call(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": uuid}),
    );
    assert_shape("get_group_by_id", &read_envelope);
    let read = ok_payload(&read_envelope);
    assert_eq!(read["name"].as_str(), Some("Work"));

    // Edit exactly what came back and send the whole group in again - the round trip the ui makes
    let mut edited = read;
    edited["name"] = json!("Work and travel");
    let updated = call("update_group", json!({"db_key": db_key, "group": edited}));
    assert_shape("update_group", &updated);

    let after = call_ok(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": uuid}),
    );
    assert_eq!(after["name"].as_str(), Some("Work and travel"));

    close_database(&db_key);
}

#[test]
fn a_blank_group_without_a_parent_is_still_a_group() {
    prepare();

    let envelope = call("new_blank_group", json!({ "mark_as_category": true }));
    assert_shape("new_blank_group", &envelope);

    let group = ok_payload(&envelope);
    assert!(
        !uuid_of(&group).is_empty(),
        "a blank group has its uuid already: {}",
        group
    );
}

#[test]
fn a_group_moves_into_another_group() {
    let db_key = key_of("group-move");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let moved = new_group(&db_key, "Moved", &root);
    let target = new_group(&db_key, "Target", &root);

    let envelope = call(
        "move_group",
        json!({
            "db_key": db_key,
            "group_uuid": uuid_of(&moved),
            "new_parent_uuid": uuid_of(&target),
        }),
    );
    assert_shape("move_group", &envelope);

    let after = call_ok(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": uuid_of(&moved)}),
    );
    assert_eq!(
        after["parent_group_uuid"].as_str(),
        Some(uuid_of(&target)),
        "the group has to sit under its new parent"
    );

    close_database(&db_key);
}

#[test]
fn a_group_is_cloned_and_the_copy_has_its_own_uuid() {
    let db_key = key_of("group-clone");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let original = new_group(&db_key, "Original", &root);

    let envelope = call(
        "clone_group",
        json!({
            "db_key": db_key,
            "group_uuid": uuid_of(&original),
            "new_name": "Copy",
        }),
    );
    assert_shape("clone_group", &envelope);

    let clone_uuid = ok_payload(&envelope)["group_uuid"]
        .as_str()
        .expect("cloning answers with the uuid of the copy")
        .to_string();
    assert_ne!(
        clone_uuid,
        uuid_of(&original),
        "a copy is a different group"
    );

    let clone = call_ok(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": clone_uuid}),
    );
    assert_eq!(clone["name"].as_str(), Some("Copy"));

    close_database(&db_key);
}

#[test]
fn sub_groups_are_sorted_by_the_criteria_the_wire_spells() {
    let db_key = key_of("group-sort");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    new_group(&db_key, "Beta", &root);
    new_group(&db_key, "Alpha", &root);

    let envelope = call(
        "sort_sub_groups",
        json!({"db_key": db_key, "group_uuid": root, "criteria": "a_to_z"}),
    );
    assert_shape("sort_sub_groups", &envelope);

    let names = child_names(&db_key, &root);
    assert_eq!(
        names,
        vec!["Alpha".to_string(), "Beta".to_string()],
        "a_to_z has to reach the core as its AtoZ"
    );

    call_ok(
        "sort_sub_groups",
        json!({"db_key": db_key, "group_uuid": root, "criteria": "z_to_a"}),
    );
    assert_eq!(
        child_names(&db_key, &root),
        vec!["Beta".to_string(), "Alpha".to_string()]
    );

    close_database(&db_key);
}

#[test]
fn an_unknown_sort_criteria_is_refused_before_the_database_is_touched() {
    let db_key = key_of("group-sort-unknown");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let envelope = call(
        "sort_sub_groups",
        json!({"db_key": db_key, "group_uuid": root, "criteria": "AtoZ"}),
    );

    assert!(
        envelope.contains(r#""kind":"InvalidArguments""#),
        "the wire spells the criteria snake_case, the core's own name is not accepted: {}",
        envelope
    );

    close_database(&db_key);
}

// Only entries go to the recycle bin (pass-docs, Step 69): a deleted group is gone for good
#[test]
fn a_deleted_group_is_gone_for_good() {
    let db_key = key_of("group-delete");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let group = new_group(&db_key, "Doomed", &root);
    let uuid = uuid_of(&group).to_string();

    let deleted = call("delete_group", group_id_args(&db_key, &uuid));
    assert_shape("delete_group", &deleted);

    let gone = call(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": uuid}),
    );
    assert!(
        gone.starts_with(r#"{"err":"#),
        "a deleted group is not found any more: {}",
        gone
    );

    close_database(&db_key);
}

#[test]
fn a_uuid_that_is_not_a_uuid_is_an_argument_error_and_not_a_lookup() {
    let db_key = key_of("group-bad-uuid");
    open_database(&db_key);

    let envelope = call(
        "get_group_by_id",
        json!({"db_key": db_key, "group_uuid": "not-a-uuid"}),
    );

    assert!(
        envelope.contains(r#""kind":"InvalidArguments""#),
        "{}",
        envelope
    );

    close_database(&db_key);
}

#[test]
fn a_group_of_a_database_that_is_not_open_says_so() {
    prepare();

    let envelope = run_with_bytes(
        "groups_summary_data",
        &db_key_args("content://test/never-opened-groups.kdbx"),
        None,
    )
    .envelope;

    assert!(envelope.contains("DbKeyNotFound"), "{}", envelope);
}

#[test]
fn bytes_are_refused_by_a_command_that_works_on_an_open_database() {
    prepare();

    let answer = run_with_bytes(
        "groups_summary_data",
        &db_key_args(&key_of("group-bytes")),
        Some(vec![1, 2, 3]),
    );

    assert!(
        answer.envelope.contains(r#""kind":"InvalidArguments""#),
        "{}",
        answer.envelope
    );
}

fn group_id_args(db_key: &str, group_uuid: &str) -> Value {
    json!({"db_key": db_key, "group_uuid": group_uuid})
}

/// The names of the child groups of a group, in stored order.
fn child_names(db_key: &str, group_uuid: &str) -> Vec<String> {
    let tree = call_ok("groups_summary_data", json!({ "db_key": db_key }));
    let groups = &tree["groups"];

    groups[group_uuid]["group_uuids"]
        .as_array()
        .expect("a group lists its children")
        .iter()
        .map(|child| {
            let uuid = child.as_str().expect("a child uuid is a string");
            groups[uuid]["name"]
                .as_str()
                .expect("a group has a name")
                .to_string()
        })
        .collect()
}
