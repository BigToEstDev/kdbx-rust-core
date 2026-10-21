//! Скрытые поля базы (`Meta/MemoryProtection`) через настройки базы (Step 66).
//!
//! Клиент читает флаги через `get_db_settings`, меняет и отправляет обратно через `set_db_settings`; после
//! сохранения и повторного открытия файла значения должны остаться. Ядро флаги не применяет — их применяет
//! приложение.

mod common;

use kdbx_rust_core::db_service::{self, DbSettings, NewDatabase};
use serde_json::{json, Value};

const PASSWORD: &str = "memory-protection-1234";

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "okp_memory_protection_{}_{}.kdbx",
        name,
        std::process::id()
    ));
    p.to_str().unwrap().to_string()
}

// KDF уменьшен, чтобы тест был быстрым в debug
fn create_db(db_key: &str) {
    common::init();
    let _ = std::fs::remove_file(db_key);
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = json!("MemoryProtection");
    v["database_file_name"] = json!(db_key);
    v["password"] = json!(PASSWORD);
    v["kdf"] = json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();
    db_service::create_kdbx(new_db).unwrap();
}

// Флаги так, как их видит клиент в форме настроек
fn protection(db_key: &str) -> Value {
    let v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    v["meta"]["memory_protection"].clone()
}

fn set_protection(db_key: &str, protection: Value) {
    let mut v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    v["meta"]["memory_protection"] = protection;
    let settings: DbSettings = serde_json::from_value(v).unwrap();
    db_service::set_db_settings(db_key, settings, None).unwrap();
}

fn save_and_reopen(db_key: &str) {
    db_service::save_kdbx_with_backup(db_key, None, false).unwrap();
    db_service::close_kdbx(db_key).unwrap();
    db_service::load_kdbx(db_key, Some(PASSWORD), None).unwrap();
}

fn cleanup(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

// Как KeePass и KeePassXC: в новой базе скрыт только пароль
#[test]
fn a_new_database_protects_only_the_password() {
    let db_key = temp_path("new");
    create_db(&db_key);

    let read = protection(&db_key);

    cleanup(&db_key);
    assert_eq!(
        read,
        json!({
            "protect_title": false,
            "protect_username": false,
            "protect_password": true,
            "protect_url": false,
            "protect_notes": false,
        })
    );
}

#[test]
fn the_protection_set_survives_save_and_reopen() {
    let db_key = temp_path("set");
    create_db(&db_key);
    let changed = json!({
        "protect_title": true,
        "protect_username": false,
        "protect_password": false,
        "protect_url": true,
        "protect_notes": true,
    });

    set_protection(&db_key, changed.clone());
    let after_set = protection(&db_key);
    save_and_reopen(&db_key);
    let after_reopen = protection(&db_key);

    cleanup(&db_key);
    assert_eq!(after_set, changed, "после set_db_settings");
    assert_eq!(after_reopen, changed, "после сохранения и открытия");
}

// Имя базы и лимиты истории в той же форме — смена флагов их не трогает
#[test]
fn changing_the_protection_keeps_the_rest_of_the_settings() {
    let db_key = temp_path("rest");
    create_db(&db_key);
    let before = serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();

    set_protection(
        &db_key,
        json!({
            "protect_title": true,
            "protect_username": true,
            "protect_password": true,
            "protect_url": true,
            "protect_notes": true,
        }),
    );
    save_and_reopen(&db_key);
    let after = serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();

    cleanup(&db_key);
    for key in ["database_name", "history_max_items", "history_max_size"] {
        assert_eq!(after["meta"][key], before["meta"][key], "{}", key);
    }
}
