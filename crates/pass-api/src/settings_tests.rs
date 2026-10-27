//! Settings and key files across the boundary.
//!
//! Nothing here touches the disk: since Step 29 a new key file comes back as bytes, for the app to write
//! through SAF.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{close_database, key_of, ok_payload, open_database};

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

#[test]
fn the_settings_of_a_database_are_read_and_written_back() {
    let db_key = key_of("settings-round-trip");
    open_database(&db_key);

    let envelope = call("get_db_settings", json!({ "db_key": db_key }));
    assert_shape("get_db_settings", &envelope);

    let mut settings = ok_payload(&envelope);
    assert_eq!(
        settings["database_file_name"].as_str(),
        Some(db_key.as_str()),
        "the settings name the database they belong to: {}",
        settings
    );

    // The name of the database lives in its metadata, and editing it is what a settings screen does
    settings["meta"]["database_name"] = json!("Renamed");
    let written = call(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );
    assert_shape("set_db_settings", &written);

    let after = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(after["meta"]["database_name"].as_str(), Some("Renamed"));

    close_database(&db_key);
}

// The version and the compression of the file go across as the screen shows them (Step 64): the compression
// both ways, the version out only
#[test]
fn the_compression_is_written_back_and_the_version_is_said() {
    let db_key = key_of("settings-file-format");
    open_database(&db_key);

    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(
        settings["kdbx_version"].as_str(),
        Some("4.1"),
        "{}",
        settings
    );
    assert_eq!(
        settings["compression"].as_str(),
        Some("GZip"),
        "{}",
        settings
    );

    settings["compression"] = json!("None");
    call_ok(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );

    let after = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(after["compression"].as_str(), Some("None"));

    close_database(&db_key);
}

// The private fields of the database go across both ways (Step 66): `meta.memory_protection`, only the password
// in a new database
#[test]
fn the_memory_protection_is_written_back() {
    let db_key = key_of("settings-memory-protection");
    open_database(&db_key);

    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    let protection = &settings["meta"]["memory_protection"];
    assert_eq!(protection["protect_password"], json!(true), "{}", settings);
    assert_eq!(protection["protect_title"], json!(false), "{}", settings);

    settings["meta"]["memory_protection"]["protect_title"] = json!(true);
    call_ok(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );

    let after = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(
        after["meta"]["memory_protection"]["protect_title"],
        json!(true)
    );

    close_database(&db_key);
}

#[test]
fn a_new_key_file_comes_back_as_bytes() {
    let answer = run_with_bytes("generate_key_file", "", None);
    assert_shape("generate_key_file", &answer.envelope);

    let content = answer
        .payload
        .expect("the key file has to come back as bytes, for the app to write through SAF");
    let xml = String::from_utf8(content).expect("a generated key file is xml");
    assert!(xml.contains("<KeyFile>"), "{}", xml);
    assert!(xml.contains(r#"<Version>2.0</Version>"#), "{}", xml);
}

#[test]
fn two_new_key_files_are_different() {
    let first = run_with_bytes("generate_key_file", "", None).payload;
    let second = run_with_bytes("generate_key_file", "", None).payload;
    assert_ne!(first, second);
}

#[test]
fn generating_a_key_file_takes_no_bytes() {
    let refused = run_with_bytes("generate_key_file", "", Some(vec![1, 2, 3])).envelope;
    assert!(refused.contains("InvalidArguments"), "{}", refused);
}

#[test]
fn a_password_over_the_limit_cannot_be_set_in_the_settings() {
    let db_key = key_of("settings-password-limit");
    open_database(&db_key);

    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    settings["password"] = json!("a".repeat(257));
    settings["password_used"] = json!(true);
    settings["password_changed"] = json!(true);
    settings["meta"]["database_name"] = json!("Renamed");

    let refused = call(
        "set_db_settings",
        json!({"db_key": db_key, "settings": settings}),
    );
    assert!(
        refused.contains(r#""kind":"PasswordTooLong""#),
        "{}",
        refused
    );

    // Refused before anything changed
    let after = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(after["meta"]["database_name"].as_str(), Some("Test"));

    close_database(&db_key);
}

#[test]
fn the_settings_of_a_database_that_is_not_open_say_so() {
    let envelope = call(
        "get_db_settings",
        json!({"db_key": "content://test/never-opened-settings.kdbx"}),
    );

    assert!(envelope.contains("DbKeyNotFound"), "{}", envelope);
}

// --- One KDF pass timed for the open time on the screen (Step 68) ---

#[test]
fn a_kdf_pass_is_measured_and_the_kdf_stays_as_is() {
    let db_key = key_of("settings-kdf-pass");
    open_database(&db_key);
    let before = call_ok("get_db_settings", json!({ "db_key": db_key }))["kdf"].clone();

    let envelope = call("measure_kdf_pass", json!({ "db_key": db_key }));
    assert_shape("measure_kdf_pass", &envelope);

    let after = call_ok("get_db_settings", json!({ "db_key": db_key }))["kdf"].clone();
    assert_eq!(after, before);
    close_database(&db_key);
}

#[test]
fn a_kdf_pass_of_a_database_that_is_not_open_says_so() {
    let envelope = call(
        "measure_kdf_pass",
        json!({"db_key": "content://test/never-opened-kdf-pass.kdbx"}),
    );

    assert!(envelope.contains("DbKeyNotFound"), "{}", envelope);
}

// --- A changed key file goes in as content (Step 31) ---

fn key_file_json(name: &str, content: &[u8]) -> Value {
    json!({ "name": name, "content": crate::key_file::encode(content) })
}

fn unlock_with(db_key: &str, key_file: Value) -> String {
    call("lock_kdbx", json!({ "db_key": db_key }));
    call(
        "unlock_kdbx",
        json!({
            "db_key": db_key,
            "password": crate::test_support::TEST_PASSWORD,
            "key_file": key_file,
        }),
    )
}

#[test]
fn a_key_file_is_added_in_the_settings_as_content() {
    let db_key = key_of("settings-add-key-file");
    open_database(&db_key);
    let content = run_with_bytes("generate_key_file", "", None)
        .payload
        .expect("a generated key file");

    let mut settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    settings["key_file_used"] = json!(true);
    settings["key_file_changed"] = json!(true);
    let written = call(
        "set_db_settings",
        json!({
            "db_key": db_key,
            "settings": settings,
            "key_file": key_file_json("added.keyx", &content),
        }),
    );
    assert!(written.starts_with(r#"{"ok":"#), "{}", written);

    let after = call_ok("get_db_settings", json!({ "db_key": db_key }));
    assert_eq!(after["key_file_name"].as_str(), Some("added.keyx"));

    // The composite key changed: the password alone no longer unlocks, with the key file it does
    let refused = unlock_with(&db_key, Value::Null);
    assert!(refused.contains("InvalidCredentials"), "{}", refused);
    let unlocked = unlock_with(&db_key, key_file_json("added.keyx", &content));
    assert!(unlocked.starts_with(r#"{"ok":"#), "{}", unlocked);

    close_database(&db_key);
}

#[test]
fn a_key_file_the_settings_do_not_change_is_refused() {
    let db_key = key_of("settings-unasked-key-file");
    open_database(&db_key);

    let settings = call_ok("get_db_settings", json!({ "db_key": db_key }));
    let refused = call(
        "set_db_settings",
        json!({
            "db_key": db_key,
            "settings": settings,
            "key_file": key_file_json("k.keyx", b"some key"),
        }),
    );
    assert!(refused.contains(r#""kind":"DataError""#), "{}", refused);

    close_database(&db_key);
}
