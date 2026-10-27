//! The shape of an answer, pinned in a file both sides read.
//!
//! A contract test does not check values - they change with every run - but the **shape**: which keys an
//! answer has and of what type. That is exactly what breaks the app silently when a field is renamed in
//! the core, and exactly what a compiler cannot see across the boundary.
//!
//! The files live in `contract/` next to `commands.json` and are part of the source. When a shape
//! legitimately changes, rerun the tests with `UPDATE_CONTRACT=1`, look at the diff, and commit it - the
//! app side (Kotlin on android, TypeScript on desktop) then fails until its own model is updated.

use serde_json::{json, Value};

/// The key a uuid keyed map gets in the shape, standing for every entry of it.
const UUID_KEY: &str = "<uuid>";

/// Replaces every value with the name of its type, recursively.
pub(crate) fn shape(value: &Value) -> Value {
    match value {
        // An object is either a struct, whose keys are the contract, or a map keyed by uuid - the tree
        // of groups is one. Keeping a generated uuid in the file would pin the random name of one test
        // group and change on every run, so such a key collapses into `<uuid>`: what matters there is
        // the shape of the value, and every entry has the same one
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (normalise_key(key), shape(value)))
                .collect(),
        ),
        // Only the first element: a list is homogeneous here, and pinning its length would make the
        // file depend on the test data
        Value::Array(items) => match items.first() {
            Some(first) => json!([shape(first)]),
            None => json!([]),
        },
        Value::String(_) => json!("string"),
        Value::Number(_) => json!("number"),
        Value::Bool(_) => json!("bool"),
        // A null tells us nothing about the type, and an Option that happens to be None in the test
        // would pin the wrong shape. The name says so out loud
        Value::Null => json!("null-in-this-sample"),
    }
}

/// The key a map whose keys are data - the fields of an entry, by name - gets in the shape.
const DATA_KEY: &str = "<key>";

/// The same as [`assert_shape`], for an answer that is a map whose keys are *data* rather than a
/// contract: the fields of an entry are named by the preset and by whatever the user added.
///
/// Pinning those names would make the file a copy of the test fixture and would break as soon as the
/// fixture changed, so every key collapses into `<key>` and what stays pinned is the only promise
/// there is: the answer is an object of that value type.
pub(crate) fn assert_shape_of_map(command: &str, envelope: &str) {
    let ok = ok_of(command, envelope);
    let map = ok
        .as_object()
        .unwrap_or_else(|| panic!("the answer of {} is not an object: {}", command, envelope));

    let collapsed: Value = Value::Object(
        map.iter()
            .map(|(_, value)| (DATA_KEY.to_string(), shape(value)))
            .collect(),
    );

    compare(command, &collapsed);
}

fn normalise_key(key: &str) -> String {
    match uuid::Uuid::parse_str(key) {
        Ok(_) => UUID_KEY.to_string(),
        Err(_) => key.to_string(),
    }
}

/// The `ok` payload, or a failure naming the command - an `err` here means the test set the call up
/// wrongly, and the message has to say which call.
fn ok_of(command: &str, envelope: &str) -> Value {
    let parsed: Value = serde_json::from_str(envelope).expect("the envelope is not json");

    parsed
        .get("ok")
        .unwrap_or_else(|| panic!("the answer of {} carries no 'ok': {}", command, envelope))
        .clone()
}

/// Serialises access to the files.
///
/// Several tests legitimately go through the same command - every test that needs an entry inserts
/// one - and cargo runs them in parallel. With UPDATE_CONTRACT one of them can then read a file while
/// another is writing it, and see it half written. The lock is around write *and* read, so a file is
/// never observed between the two.
static FILES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Writes or checks `contract/<command>.json` against a shape already built.
fn compare(command: &str, shape: &Value) {
    let expected = serde_json::to_string_pretty(shape).unwrap() + "\n";
    let path = format!("{}/contract/{}.json", env!("CARGO_MANIFEST_DIR"), command);

    // A poisoned lock means another test already failed; its own panic is the one worth reading
    let _guard = FILES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if std::env::var("UPDATE_CONTRACT").is_ok() {
        std::fs::write(&path, &expected).unwrap();
    }

    let actual = std::fs::read_to_string(&path).unwrap_or_default();

    // Line endings are not part of the contract: git hands the file over with crlf on a machine with
    // core.autocrlf, and the shape is the same shape either way. Comparing the bytes would mean these
    // tests pass or fail depending on how the repository was checked out
    assert_eq!(
        normalise_line_endings(&actual),
        normalise_line_endings(&expected),
        "the shape of {} changed; check the diff, rerun with UPDATE_CONTRACT=1 and update the Kotlin model",
        command
    );
}

fn normalise_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// Compares the `ok` payload of an envelope with `contract/<command>.json`.
pub(crate) fn assert_shape(command: &str, envelope: &str) {
    let ok = ok_of(command, envelope);

    compare(command, &shape(&ok));
}

#[cfg(test)]
mod tests {
    use super::shape;
    use serde_json::json;

    #[test]
    fn every_value_becomes_the_name_of_its_type() {
        let sample = json!({"name": "db", "count": 3, "locked": false, "tags": ["a", "b"]});

        assert_eq!(
            shape(&sample),
            json!({"name": "string", "count": "number", "locked": "bool", "tags": ["string"]})
        );
    }

    // The tree of groups is a map keyed by uuid, and a generated uuid in the file would differ on
    // every run
    #[test]
    fn a_map_keyed_by_uuid_collapses_into_one_entry() {
        let sample = json!({
            "groups": {
                "c33c5b9a-b110-44f8-8f1d-17ed7c1d27b9": {"name": "Root"},
                "7b1a2c3d-0000-4000-8000-000000000000": {"name": "Work"},
            }
        });

        assert_eq!(
            shape(&sample),
            json!({"groups": {"<uuid>": {"name": "string"}}})
        );
    }

    #[test]
    fn nesting_is_kept_so_a_moved_field_is_visible() {
        let sample = json!({"db": {"key": "uri", "history": [{"index": 1}]}});

        assert_eq!(
            shape(&sample),
            json!({"db": {"key": "string", "history": [{"index": "number"}]}})
        );
    }
}
