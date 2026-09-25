//! Лимиты истории записей (`HistoryMaxItems`, `HistoryMaxSize`) через настройки базы.
//!
//! Клиент читает их через `get_db_settings`, меняет и отправляет обратно через
//! `set_db_settings`; после сохранения и повторного открытия файла значения должны остаться.
//! Размер в KeePass — `long` (байты), в диалоге задаётся в МБ, поэтому значения больше
//! `i32::MAX` законны и не должны превращаться в «без ограничения» (`-1`).

mod common;

use kdbx_rust_core::db_content;
use kdbx_rust_core::db_service::{self, DbSettings, NewDatabase};
use uuid::Uuid;

const PASSWORD: &str = "history-settings-1234";

// Умолчания KeePass для новой базы
const DEFAULT_MAX_ITEMS: i64 = 10;
const DEFAULT_MAX_SIZE: i64 = 6 * 1024 * 1024;

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "okp_history_settings_{}_{}.kdbx",
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
    v["database_name"] = serde_json::json!("HistorySettings");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();
    db_service::create_kdbx(new_db).unwrap();
}

// Лимиты так, как их видит клиент в форме настроек
fn history_limits(db_key: &str) -> (i64, i64) {
    let v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    (
        v["meta"]["history_max_items"].as_i64().unwrap(),
        v["meta"]["history_max_size"].as_i64().unwrap(),
    )
}

fn set_history_limits(db_key: &str, max_items: i64, max_size: i64) {
    let mut v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    v["meta"]["history_max_items"] = serde_json::json!(max_items);
    v["meta"]["history_max_size"] = serde_json::json!(max_size);
    let settings: DbSettings = serde_json::from_value(v).unwrap();
    db_service::set_db_settings(db_key, settings).unwrap();
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

// Раньше в «макс. размер истории» подставлялось количество версий (10 вместо 6 MiB)
#[test]
fn get_db_settings_returns_history_size_not_count() {
    let db_key = temp_path("get");
    create_db(&db_key);

    let limits = history_limits(&db_key);

    cleanup(&db_key);
    assert_eq!(limits, (DEFAULT_MAX_ITEMS, DEFAULT_MAX_SIZE));
}

// Раньше set_db_settings записывал лимиты в отдельный Meta и они терялись
#[test]
fn set_db_settings_changes_both_history_limits() {
    let db_key = temp_path("set");
    create_db(&db_key);

    set_history_limits(&db_key, 5, 1024 * 1024);
    let after_set = history_limits(&db_key);
    save_and_reopen(&db_key);
    let after_reopen = history_limits(&db_key);

    cleanup(&db_key);
    assert_eq!(after_set, (5, 1024 * 1024), "после set_db_settings");
    assert_eq!(
        after_reopen,
        (5, 1024 * 1024),
        "после сохранения и открытия"
    );
}

// 4096 МБ из диалога KeePass не влезает в i32 и раньше читалось как -1 («без ограничения»)
#[test]
fn history_max_size_above_i32_survives_save_and_reopen() {
    let db_key = temp_path("large");
    create_db(&db_key);
    let large = 4096_i64 * 1024 * 1024;

    set_history_limits(&db_key, DEFAULT_MAX_ITEMS, large);
    save_and_reopen(&db_key);
    let after_reopen = history_limits(&db_key);

    cleanup(&db_key);
    assert_eq!(after_reopen, (DEFAULT_MAX_ITEMS, large));
}

// "Без ограничения" в KeePass — -1 для обоих лимитов
#[test]
fn unlimited_history_limits_survive_save_and_reopen() {
    let db_key = temp_path("unlimited");
    create_db(&db_key);

    set_history_limits(&db_key, -1, -1);
    save_and_reopen(&db_key);
    let after_reopen = history_limits(&db_key);

    cleanup(&db_key);
    assert_eq!(after_reopen, (-1, -1));
}

// Login entry in the root group; returns its uuid
fn add_entry(db_key: &str, title: &str) -> Uuid {
    let root_uuid = db_service::groups_summary_data(db_key).unwrap().root_uuid;
    let login = db_content::standard_type_uuid_by_name("Login");
    let form = db_service::new_entry_form_data_by_id(db_key, login, Some(&root_uuid)).unwrap();
    let mut v = serde_json::to_value(&form).unwrap();
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    v["title"] = serde_json::json!(title);
    db_service::insert_entry_from_form_data(db_key, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

// Every update puts the previous state into the entry history
fn update_title(db_key: &str, entry_uuid: &Uuid, title: &str) {
    let form = db_service::get_entry_form_data_by_id(db_key, entry_uuid).unwrap();
    let mut v = serde_json::to_value(&form).unwrap();
    v["title"] = serde_json::json!(title);
    db_service::update_entry_from_form_data(db_key, serde_json::from_value(v).unwrap()).unwrap();
}

fn history_len(db_key: &str, entry_uuid: &Uuid) -> usize {
    db_service::history_entries_summary(db_key, entry_uuid)
        .unwrap()
        .len()
}

// KeePass applies new limits to all entries right away (PwDatabase.MaintainBackups after the
// settings dialog), not only to entries edited later
#[test]
fn lowering_history_limit_trims_existing_entries() {
    let db_key = temp_path("trim");
    create_db(&db_key);
    let entry = add_entry(&db_key, "v0");
    for i in 1..=5 {
        update_title(&db_key, &entry, &format!("v{}", i));
    }
    let before = history_len(&db_key, &entry);

    set_history_limits(&db_key, 2, DEFAULT_MAX_SIZE);
    let after = history_len(&db_key, &entry);

    cleanup(&db_key);
    assert_eq!(before, 5);
    assert_eq!(after, 2);
}
