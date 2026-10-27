//! Удаление версий из истории записи (`delete_history_entry_by_index`, `delete_history_entries`).
//!
//! Раньше неверный индекс и чужой `uuid` проходили молча — `Ok(())`, хотя ничего не удалено, и клиент
//! думал, что версии больше нет. Теперь это `NotFound`, а история остаётся как была (pass-docs, Step 51 п.1).

mod common;

use kdbx_rust_core::db_service::{self, NewDatabase};
use kdbx_rust_core::error::Error;
use uuid::Uuid;

const PASSWORD: &str = "history-delete-1234";

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "okp_history_delete_{}_{}.kdbx",
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
    v["database_name"] = serde_json::json!("HistoryDelete");
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

fn cleanup(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

// Entry in the root group, then `updates` saves of its title: every one leaves a version behind
fn entry_with_history(db_key: &str, updates: usize) -> Uuid {
    let root_uuid = db_service::groups_summary_data(db_key).unwrap().root_uuid;
    let form = db_service::new_entry_form_data(Some(&root_uuid));
    let mut v = serde_json::to_value(&form).unwrap();
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    common::form::set_field(&mut v, "Title", "v0");
    db_service::insert_entry_from_form_data(db_key, serde_json::from_value(v).unwrap()).unwrap();

    for i in 1..=updates {
        let form = db_service::get_entry_form_data_by_id(db_key, &uuid).unwrap();
        let mut v = serde_json::to_value(&form).unwrap();
        common::form::set_field(&mut v, "Title", &format!("v{}", i));
        db_service::update_entry_from_form_data(db_key, serde_json::from_value(v).unwrap())
            .unwrap();
    }
    uuid
}

// The titles of the versions, oldest first - as the core keeps them
fn history_titles(db_key: &str, entry_uuid: &Uuid) -> Vec<String> {
    db_service::history_entries_summary(db_key, entry_uuid)
        .unwrap()
        .into_iter()
        .map(|s| s.title.unwrap_or_default())
        .collect()
}

fn is_not_found<T: std::fmt::Debug>(result: Result<T, Error>) -> bool {
    matches!(result, Err(Error::NotFound(_)))
}

#[test]
fn a_version_is_deleted_by_its_index() {
    let db_key = temp_path("one");
    create_db(&db_key);
    let entry = entry_with_history(&db_key, 3);

    let deleted = db_service::delete_history_entry_by_index(&db_key, &entry, 1);
    let titles = history_titles(&db_key, &entry);

    cleanup(&db_key);
    assert!(deleted.is_ok());
    assert_eq!(titles, vec!["v0", "v2"]);
}

#[test]
fn an_index_with_no_version_is_refused_and_the_history_stays() {
    let db_key = temp_path("index");
    create_db(&db_key);
    let entry = entry_with_history(&db_key, 2);

    let past_the_end = db_service::delete_history_entry_by_index(&db_key, &entry, 2);
    let negative = db_service::delete_history_entry_by_index(&db_key, &entry, -1);
    let titles = history_titles(&db_key, &entry);

    cleanup(&db_key);
    assert!(is_not_found(past_the_end));
    assert!(is_not_found(negative));
    assert_eq!(titles, vec!["v0", "v1"]);
}

#[test]
fn deleting_from_an_entry_that_is_not_there_is_refused() {
    let db_key = temp_path("missing");
    create_db(&db_key);
    let stranger = Uuid::new_v4();

    let one = db_service::delete_history_entry_by_index(&db_key, &stranger, 0);
    let all = db_service::delete_history_entries(&db_key, &stranger);

    cleanup(&db_key);
    assert!(is_not_found(one));
    assert!(is_not_found(all));
}

#[test]
fn the_whole_history_is_deleted_and_an_entry_without_one_is_fine() {
    let db_key = temp_path("all");
    create_db(&db_key);
    let with = entry_with_history(&db_key, 2);
    let without = entry_with_history(&db_key, 0);

    let deleted = db_service::delete_history_entries(&db_key, &with);
    let nothing_to_delete = db_service::delete_history_entries(&db_key, &without);
    let left = history_titles(&db_key, &with);
    let current = db_service::get_entry_form_data_by_id(&db_key, &with).unwrap();
    let title =
        common::form::field(&serde_json::to_value(&current).unwrap(), "Title").map(String::from);

    cleanup(&db_key);
    assert!(deleted.is_ok());
    assert!(nothing_to_delete.is_ok());
    assert!(left.is_empty());
    // The entry itself survives losing its history
    assert_eq!(title.as_deref(), Some("v2"));
}
