//! What every test of the boundary needs: a real database, built through the boundary itself.
//!
//! The tests here run on the host, without a device and without a file: a database is created through
//! `create_and_write_to_writer` exactly as Android does it, and the bytes stay in memory. That is the
//! same path the app takes, so a test failing here is a bug the device would have shown.

use crate::dispatch::run_with_bytes;
use crate::key_store;

/// The first four bytes of any kdbx file.
pub(crate) const KDBX_SIGNATURE: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

pub(crate) const TEST_PASSWORD: &str = "open sesame";

/// The core keeps open databases in one process wide store keyed by db_key, and cargo runs tests in
/// parallel - so every test works on a key of its own. A shared key made them close each other's
/// database.
pub(crate) fn key_of(test: &str) -> String {
    format!("content://test/{}.kdbx", test)
}

/// Argon2 with the core's defaults costs about a second per call and these tests are not about the kdf,
/// so the cheapest sane parameters keep the suite fast.
pub(crate) fn new_db_args(db_key: &str) -> String {
    format!(
        r#"{{
    "database_name": "Test",
    "database_description": "Created by the bridge tests",
    "database_file_name": "{}",
    "file_name": "lifecycle.kdbx",
    "kdf": {{"algorithm": "Argon2id", "memory": 16384, "iterations": 2, "parallelism": 1, "salt": []}},
    "cipher_id": "Aes256",
    "password": "{}",
    "key_file_name": null
}}"#,
        db_key, TEST_PASSWORD
    )
}

pub(crate) fn db_key_args(db_key: &str) -> String {
    format!(r#"{{"db_key":"{}"}}"#, db_key)
}

pub(crate) fn read_args(db_key: &str, password: &str) -> String {
    format!(
        r#"{{"db_key":"{}","password":"{}","file_name":"lifecycle.kdbx"}}"#,
        db_key, password
    )
}

/// Every test needs the key store the core asks for, and installing it twice is a no-op.
pub(crate) fn prepare() {
    key_store::install();
}

/// A database open in the core under `db_key`, ready to be worked on. Its bytes are dropped: a test
/// about groups is not about the file.
pub(crate) fn open_database(db_key: &str) {
    prepare();

    let created = run_with_bytes("create_and_write_to_writer", &new_db_args(db_key), None);
    assert!(
        created.envelope.starts_with(r#"{"ok":"#),
        "the fixture database could not be created: {}",
        created.envelope
    );
}

/// Closes what `open_database` opened. Tests call it at the end so a failing one does not leave a
/// database behind in the store shared by the whole process.
pub(crate) fn close_database(db_key: &str) {
    run_with_bytes("close_kdbx", &db_key_args(db_key), None);
}

/// The `ok` payload of an envelope, for a test that wants to look inside the answer.
/// The value of a field of an entry form, by its key - the form is one list `fields`, Title and
/// Notes too (Step 45).
pub(crate) fn form_field<'a>(form: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    form["fields"]
        .as_array()?
        .iter()
        .find(|f| f["key"] == key)
        .and_then(|f| f["value"].as_str())
}

/// Sets the value of a field of an entry form. The field has to be there: a blank form carries the
/// kdbx standard fields.
pub(crate) fn set_form_field(form: &mut serde_json::Value, key: &str, value: &str) {
    let field = form["fields"]
        .as_array_mut()
        .expect("an entry form has fields")
        .iter_mut()
        .find(|f| f["key"] == key)
        .unwrap_or_else(|| panic!("the form has no field {}", key));
    field["value"] = serde_json::json!(value);
}

pub(crate) fn ok_payload(envelope: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(envelope).expect("the envelope is not json");

    parsed
        .get("ok")
        .unwrap_or_else(|| panic!("the answer carries no 'ok': {}", envelope))
        .clone()
}
