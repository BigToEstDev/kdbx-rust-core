//! Two factor codes across the boundary.
//!
//! The token itself is time based, so nothing here asserts its value - only that a token of the right
//! shape comes back, that `ttl` says how long it is good for, and that the settings reach the core in
//! the wire's own spelling.

use serde_json::{json, Value};

use crate::contract::assert_shape;
use crate::dispatch::run_with_bytes;
use crate::test_support::{close_database, key_of, ok_payload, open_database, set_form_field};

/// A valid base32 secret, the format an authenticator app shows behind its qr code.
const SECRET: &str = "JBSWY3DPEHPK3PXP";

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

fn new_entry(db_key: &str) -> String {
    let root = root_uuid(db_key);

    let mut form = call_ok("new_entry_form_data", json!({ "parent_group_uuid": root }));
    set_form_field(&mut form, "Title", "With 2fa");
    call_ok(
        "insert_entry_from_form_data",
        json!({"db_key": db_key, "form_data": form}),
    );

    form["uuid"]
        .as_str()
        .expect("a form has a uuid")
        .to_string()
}

#[test]
fn an_entry_gets_a_code_and_then_loses_it() {
    let db_key = key_of("otp-round-trip");
    open_database(&db_key);
    let uuid = new_entry(&db_key);

    // Nothing yet: an entry without 2fa is simply absent from the answer, not an error
    let before = call_ok(
        "entry_list_current_otps",
        json!({"db_key": db_key, "entry_uuids": [uuid]}),
    );
    assert!(
        before.as_array().expect("a list").is_empty(),
        "an entry without 2fa has no token: {}",
        before
    );

    let set = call(
        "set_entry_otp",
        json!({
            "db_key": db_key,
            "entry_uuid": uuid,
            "secret_or_url": SECRET,
            "period": 30,
            "digits": 6,
            "hash_algorithm": "sha1",
        }),
    );
    assert_shape("set_entry_otp", &set);

    let envelope = call(
        "entry_list_current_otps",
        json!({"db_key": db_key, "entry_uuids": [uuid]}),
    );
    assert_shape("entry_list_current_otps", &envelope);

    let tokens = ok_payload(&envelope);
    let token = &tokens.as_array().expect("a list")[0];
    assert_eq!(token["entry_uuid"].as_str(), Some(uuid.as_str()));
    assert_eq!(
        token["token"].as_str().map(str::len),
        Some(6),
        "six digits were asked for: {}",
        token
    );
    let ttl = token["ttl"]
        .as_u64()
        .expect("a token says how long it lives");
    assert!(ttl > 0 && ttl <= 30, "ttl is within the period: {}", token);

    let deleted = call(
        "delete_entry_otp",
        json!({"db_key": db_key, "entry_uuid": uuid}),
    );
    assert_shape("delete_entry_otp", &deleted);

    let after = call_ok(
        "entry_list_current_otps",
        json!({"db_key": db_key, "entry_uuids": [uuid]}),
    );
    assert!(
        after.as_array().expect("a list").is_empty(),
        "the 2fa is gone: {}",
        after
    );

    close_database(&db_key);
}

#[test]
fn the_settings_become_a_url_and_the_url_is_recognised() {
    let envelope = call(
        "form_otp_url",
        json!({
            "secret_or_url": SECRET,
            "period": 30,
            "digits": 8,
            "hash_algorithm": "sha256",
        }),
    );
    assert_shape("form_otp_url", &envelope);

    let url = ok_payload(&envelope)["otp_url"]
        .as_str()
        .expect("the url is a string")
        .to_string();
    assert!(url.starts_with("otpauth://"), "{}", url);
    assert!(
        url.contains("digits=8") && url.contains("SHA256"),
        "the settings have to be in the url: {}",
        url
    );

    // And the core reads back what it wrote
    let checked = call("is_valid_otp_url", json!({ "otp_url": url }));
    assert_shape("is_valid_otp_url", &checked);
    assert_eq!(ok_payload(&checked)["valid"].as_bool(), Some(true));
}

#[test]
fn a_url_that_is_not_an_otp_url_is_an_answer_and_not_a_failure() {
    let envelope = call(
        "is_valid_otp_url",
        json!({"otp_url": "https://example.org"}),
    );

    assert!(envelope.starts_with(r#"{"ok":"#), "{}", envelope);
    assert_eq!(ok_payload(&envelope)["valid"].as_bool(), Some(false));
}

#[test]
fn a_secret_that_cannot_be_decoded_leaves_the_entry_alone() {
    let db_key = key_of("otp-bad-secret");
    open_database(&db_key);
    let uuid = new_entry(&db_key);

    let envelope = call(
        "set_entry_otp",
        json!({
            "db_key": db_key,
            "entry_uuid": uuid,
            "secret_or_url": "not base32 at all!",
            "period": 30,
            "digits": 6,
            "hash_algorithm": "sha1",
        }),
    );

    assert!(
        envelope.starts_with(r#"{"err":"#),
        "an undecodable secret has to be refused: {}",
        envelope
    );

    let after = call_ok(
        "entry_list_current_otps",
        json!({"db_key": db_key, "entry_uuids": [uuid]}),
    );
    assert!(
        after.as_array().expect("a list").is_empty(),
        "the entry has no 2fa after a refused one: {}",
        after
    );

    close_database(&db_key);
}

#[test]
fn the_core_spelling_of_the_algorithm_is_not_accepted_from_the_wire() {
    let envelope = call(
        "form_otp_url",
        json!({
            "secret_or_url": SECRET,
            "period": 30,
            "digits": 6,
            "hash_algorithm": "SHA1",
        }),
    );

    assert!(
        envelope.contains(r#""kind":"InvalidArguments""#),
        "the wire spells the algorithm snake_case: {}",
        envelope
    );
}

#[test]
fn asking_for_the_tokens_of_a_database_that_is_not_open_says_so() {
    let envelope = call(
        "entry_list_current_otps",
        json!({"db_key": "content://test/never-opened-otp.kdbx", "entry_uuids": []}),
    );

    assert!(envelope.contains("DbKeyNotFound"), "{}", envelope);
}
