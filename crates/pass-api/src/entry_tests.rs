//! Entries across the boundary, on a real database held in memory.
//!
//! As with the groups, the point is the boundary rather than the core: the form of an entry survives
//! the round trip through json, the category argument reaches the core in its own spelling, and every
//! answer keeps the shape the contract files pin for Kotlin.

use serde_json::{json, Value};

use crate::contract::{assert_shape, assert_shape_of_map};
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

/// A filled in form of a new entry, as the ui would build it: ask for a blank form, set the
/// title, send it back.
fn new_entry(db_key: &str, title: &str, parent_group_uuid: &str) -> Value {
    let mut form = call_ok(
        "new_entry_form_data",
        json!({ "parent_group_uuid": parent_group_uuid }),
    );
    set_form_field(&mut form, "Title", title);

    let envelope = call(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );
    assert!(
        envelope.starts_with(r#"{"ok":"#),
        "insert_entry_from_form_data failed: {}",
        envelope
    );
    assert_shape("insert_entry_from_form_data", &envelope);

    form
}

fn uuid_of(form: &Value) -> &str {
    form["uuid"].as_str().expect("an entry form has a uuid")
}

/// The titles of the entries of a category, which is what a list screen shows.
fn titles(db_key: &str, category: Value) -> Vec<String> {
    call_ok(
        "entry_summary_data",
        json!({"db_key": db_key, "category": category}),
    )
    .as_array()
    .expect("the summaries are a list")
    .iter()
    .filter_map(|entry| entry["title"].as_str().map(str::to_string))
    .collect()
}

#[test]
fn an_entry_is_created_listed_read_back_and_edited() {
    let db_key = key_of("entry-round-trip");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    // A blank form with the kdbx standard fields: the app lays its preset over it for the "new entry" screen
    let blank = call("new_entry_form_data", json!({ "parent_group_uuid": root }));
    assert_shape("new_entry_form_data", &blank);

    let form = new_entry(&db_key, "Mail", &root);
    let uuid = uuid_of(&form).to_string();

    // The list of a category is the list screen
    let listed = call(
        "entry_summary_data",
        json!({"db_key": db_key, "category": {"kind": "all_entries"}}),
    );
    assert_shape("entry_summary_data", &listed);
    assert_eq!(
        titles(&db_key, json!({"kind": "all_entries"})),
        vec!["Mail".to_string()]
    );

    // Read it back as a form, edit it, send the whole form in again
    let read_envelope = call(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_shape("get_entry_form_data_by_id", &read_envelope);
    let mut read = ok_payload(&read_envelope);
    assert_eq!(form_field(&read, "Title"), Some("Mail"));

    set_form_field(&mut read, "Title", "Mail and calendar");
    let updated = call(
        "update_entry_from_form_data",
        json!({"db_key": db_key, "form_data": read}),
    );
    assert_shape("update_entry_from_form_data", &updated);

    let after = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_eq!(form_field(&after, "Title"), Some("Mail and calendar"));

    close_database(&db_key);
}

#[test]
fn the_fields_of_an_entry_come_back_as_a_map_of_names_to_values() {
    let db_key = key_of("entry-fields");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let form = new_entry(&db_key, "Bank", &root);

    let envelope = call(
        "entry_key_value_fields",
        json!({"db_key": db_key, "entry_uuid": uuid_of(&form)}),
    );
    // The keys here are data - the fields of the preset, plus whatever the user added - so the
    // contract pins that this is a map of strings, not which names are in it
    assert_shape_of_map("entry_key_value_fields", &envelope);

    let fields = ok_payload(&envelope);
    assert_eq!(
        fields["Title"].as_str(),
        Some("Bank"),
        "the title has to be among the fields: {}",
        fields
    );

    close_database(&db_key);
}

#[test]
fn a_category_reaches_the_core_in_its_own_spelling() {
    let db_key = key_of("entry-category");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let group = call_ok(
        "new_blank_group_with_parent",
        json!({"parent_group_uuid": root, "mark_as_category": false}),
    );
    let mut named = group.clone();
    named["name"] = json!("Sub");
    call_ok("insert_group", json!({"db_key": db_key, "group": named}));
    let group_uuid = group["uuid"].as_str().unwrap().to_string();

    new_entry(&db_key, "In the root", &root);
    new_entry(&db_key, "In the group", &group_uuid);

    // A tagged category with a value: the core spells it {"group": "…"}, the wire spells it ours
    assert_eq!(
        titles(&db_key, json!({"kind": "group", "value": group_uuid})),
        vec!["In the group".to_string()]
    );
    // And one without a value
    assert_eq!(
        titles(&db_key, json!({"kind": "all_entries"})).len(),
        2,
        "all_entries lists both"
    );

    close_database(&db_key);
}

#[test]
fn the_core_spelling_of_a_category_is_not_accepted_from_the_wire() {
    let db_key = key_of("entry-category-spelling");
    open_database(&db_key);

    let envelope = call(
        "entry_summary_data",
        json!({"db_key": db_key, "category": "allEntries"}),
    );

    assert!(
        envelope.contains(r#""kind":"InvalidArguments""#),
        "the camelCase name of the core is not the wire format: {}",
        envelope
    );

    close_database(&db_key);
}

#[test]
fn an_entry_moves_into_another_group() {
    let db_key = key_of("entry-move");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let target = call_ok(
        "new_blank_group_with_parent",
        json!({"parent_group_uuid": root, "mark_as_category": false}),
    );
    let mut named = target.clone();
    named["name"] = json!("Target");
    call_ok("insert_group", json!({"db_key": db_key, "group": named}));
    let target_uuid = target["uuid"].as_str().unwrap().to_string();

    let form = new_entry(&db_key, "Moved", &root);

    let envelope = call(
        "move_entry",
        json!({
            "db_key": db_key,
            "entry_uuid": uuid_of(&form),
            "new_parent_uuid": target_uuid,
        }),
    );
    assert_shape("move_entry", &envelope);

    let after = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid_of(&form)}),
    );
    // The core calls the parent of an entry `group_uuid` - a name of the upstream this module keeps,
    // because it is the entry form's own json. Kotlin renames it in its dto
    assert_eq!(after["group_uuid"].as_str(), Some(target_uuid.as_str()));

    close_database(&db_key);
}

#[test]
fn an_entry_is_cloned_with_a_new_title() {
    let db_key = key_of("entry-clone");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let form = new_entry(&db_key, "Original", &root);

    let envelope = call(
        "clone_entry",
        json!({
            "db_key": db_key,
            "entry_uuid": uuid_of(&form),
            "new_title": "Copy",
            "parent_group_uuid": root,
            "keep_histories": false,
            "link_by_reference": false,
        }),
    );
    assert_shape("clone_entry", &envelope);

    let clone_uuid = ok_payload(&envelope)["entry_uuid"]
        .as_str()
        .expect("cloning answers with the uuid of the copy")
        .to_string();
    assert_ne!(clone_uuid, uuid_of(&form), "a copy is a different entry");

    let clone = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": clone_uuid}),
    );
    assert_eq!(form_field(&clone, "Title"), Some("Copy"));

    close_database(&db_key);
}

// A new database uses the recycle bin: a deleted entry is still there, in the bin. The rest of the bin is
// trash_tests
#[test]
fn a_deleted_entry_goes_to_the_recycle_bin() {
    let db_key = key_of("entry-delete");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let form = new_entry(&db_key, "Doomed", &root);
    let uuid = uuid_of(&form).to_string();

    let deleted = call(
        "delete_entry",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_shape("delete_entry", &deleted);

    // Deleted is a category of its own, which is how the ui shows the recycle bin
    assert_eq!(
        titles(&db_key, json!({"kind": "deleted"})),
        vec!["Doomed".to_string()]
    );

    close_database(&db_key);
}

#[test]
fn an_entry_that_does_not_exist_is_a_failure_with_the_kind_of_the_core() {
    let db_key = key_of("entry-missing");
    open_database(&db_key);

    let envelope = call(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": "00000000-0000-4000-8000-000000000000"}),
    );

    assert!(envelope.contains("NotFound"), "{}", envelope);

    close_database(&db_key);
}

// Two fields under one key are refused with a kind of their own, so the app can say which field to
// rename (Step 45). The form keeps a repeated key read from a foreign file - this is the guard on saving
#[test]
fn a_form_with_a_repeated_key_is_refused_with_its_own_kind() {
    let db_key = key_of("entry-repeated-key");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    let fields = form["fields"].as_array_mut().unwrap();
    let title = fields.iter().find(|f| f["key"] == "Title").unwrap().clone();
    fields.push(title);

    let refused = call(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );
    assert!(
        refused.contains(r#""kind":"DuplicateFieldKey""#),
        "{}",
        refused
    );

    close_database(&db_key);
}

// The type our app gives a field travels as a string both ways, one the app does not know too: it is
// the app's, kept by the core in the entry's CustomData (Step 76)
#[test]
fn the_type_of_a_field_travels_both_ways() {
    let db_key = key_of("entry-field-type");
    open_database(&db_key);
    let root = root_uuid(&db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", "Bank");
    let fields = form["fields"].as_array_mut().unwrap();
    for (key, field_type) in [("Phone", "phone"), ("Card", "from-a-newer-client")] {
        fields.push(json!({
            "key": key,
            "value": "1234",
            "protected": false,
            "data_type": "Text",
            "field_type": field_type,
        }));
    }
    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );

    let read = call_ok(
        "get_entry_form_data_by_id",
        json!({"db_key": db_key, "entry_uuid": uuid_of(&form)}),
    );
    let type_of = |key: &str| {
        read["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["key"] == key)
            .map(|f| f["field_type"].clone())
    };
    assert_eq!(type_of("Phone"), Some(json!("phone")));
    assert_eq!(type_of("Card"), Some(json!("from-a-newer-client")));
    assert_eq!(type_of("Title"), Some(Value::Null));

    close_database(&db_key);
}
