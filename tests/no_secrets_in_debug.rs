//! Секреты не попадают в `Debug` публичных форм (Step 31).
//!
//! Производный `Debug` печатал все поля, и один `debug!("{:?}", form)` клал бы мастер-пароль или пароль
//! записи в logcat — release пишет `warn` и выше (Step 24). Здесь формы берутся так, как их получает
//! клиент, через API ядра; внутренние типы проверяются юнит-тестами рядом с ними (`src/redacted.rs`).

mod common;

use std::io::Cursor;

use kdbx_rust_core::db_service::{self, NewDatabase};

const PASSWORD: &str = "master-s3cret";
const ENTRY_PASSWORD: &str = "entry-s3cret";

fn assert_hides(debug: &str, secret: &str) {
    assert!(!debug.contains(secret), "секрет в Debug-выводе: {}", debug);
    assert!(debug.contains("***"), "ничего не скрыто: {}", debug);
}

fn new_db(db_key: &str) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    // Дешёвый Argon2: тест не про KDF
    v["kdf"] = serde_json::json!({"algorithm": "Argon2id", "memory": 1048576, "iterations": 1, "parallelism": 1});
    serde_json::from_value(v).unwrap()
}

#[test]
fn a_new_database_does_not_show_its_password() {
    assert_hides(
        &format!("{:?}", new_db("content://test/debug-new")),
        PASSWORD,
    );
}

#[test]
fn the_settings_do_not_show_a_new_password() {
    common::init();
    let db_key = "content://test/debug-settings";
    db_service::create_and_write_to_writer(&mut Cursor::new(Vec::new()), new_db(db_key), None)
        .unwrap();

    let mut v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    v["password"] = serde_json::json!(PASSWORD);
    let settings: db_service::DbSettings = serde_json::from_value(v).unwrap();

    assert_hides(&format!("{:?}", settings), PASSWORD);
    db_service::close_kdbx(db_key).unwrap();
}

#[test]
fn an_entry_form_does_not_show_its_fields() {
    common::init();
    let db_key = "content://test/debug-entry";
    db_service::create_and_write_to_writer(&mut Cursor::new(Vec::new()), new_db(db_key), None)
        .unwrap();

    let root = db_service::groups_summary_data(db_key).unwrap().root_uuid;
    let form = db_service::new_entry_form_data(Some(&root));

    let mut v = serde_json::to_value(&form).unwrap();
    for field in v["preset_fields"].as_array_mut().unwrap().iter_mut() {
        if field["key"] == "Password" {
            field["value"] = serde_json::json!(ENTRY_PASSWORD);
        }
    }
    let form: db_service::EntryFormData = serde_json::from_value(v).unwrap();

    let debug = format!("{:?}", form);
    assert_hides(&debug, ENTRY_PASSWORD);
    assert!(debug.contains("Password"), "имя поля видно: {}", debug);
    db_service::close_kdbx(db_key).unwrap();
}
