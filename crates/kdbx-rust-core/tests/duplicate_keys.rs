//! Две строки записи с одним ключом (Step 45).
//!
//! Формат не запрещает две `<String>` с одним `<Key>` в записи, и чужой клиент может такую записать.
//! Ядро читает обе, отдаёт обе в форме и пишет обе обратно в их порядке; форму с дублем на сохранение
//! не принимает (`DuplicateFieldKey`) - приложение просит переименовать поле.
//!
//! Фикстура `duplicate_keys_41.kdbx` собрана pykeepass (tools/kdbx-oracle/gen_fixtures.py), значения
//! продублированы там - менять вместе.

mod common;

use std::path::PathBuf;

use kdbx_rust_core::db_service::{self, EntryCategory, EntryFormData};
use kdbx_rust_core::error::Error;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "duplicate_keys_41.kdbx";
const TITLE: &str = "Dup";
const EXTRA: &[(&str, &str)] = &[
    ("PIN", "1111"),
    ("Note", "first"),
    ("PIN", "2222"),
    ("Note", "second"),
];

fn open_copy(suffix: &str) -> String {
    common::init();
    let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source.push("tests/resources");
    source.push(FIXTURE);
    let mut target = std::env::temp_dir();
    target.push(format!("dup_keys_{}_{}", std::process::id(), suffix));
    let db_key = target.to_str().unwrap().to_string();
    std::fs::copy(source, &db_key).unwrap();
    db_service::load_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_key
}

fn close(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

fn entry_uuid(db_key: &str) -> uuid::Uuid {
    let entries = db_service::entry_summary_data(db_key, EntryCategory::AllEntries).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.title.as_deref() == Some(TITLE))
        .expect("запись с дублями");
    uuid::Uuid::parse_str(&entry.uuid).unwrap()
}

// Поля формы, кроме стандартных KDBX, - в порядке записи
fn extra_fields(form: &serde_json::Value) -> Vec<(String, String)> {
    form["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["key"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap_or_default().to_string(),
            )
        })
        .filter(|(k, _)| k == "PIN" || k == "Note")
        .collect()
}

fn expected() -> Vec<(String, String)> {
    EXTRA
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn form_json(db_key: &str) -> serde_json::Value {
    let form = db_service::get_entry_form_data_by_id(db_key, &entry_uuid(db_key)).unwrap();
    serde_json::to_value(&form).unwrap()
}

#[test]
fn both_fields_of_a_repeated_key_survive_reading_and_saving() {
    let db_key = open_copy("resave.kdbx");
    assert_eq!(
        extra_fields(&form_json(&db_key)),
        expected(),
        "после чтения"
    );

    let saved = format!("{}.saved", db_key);
    db_service::save_to_db_file(&db_key, &saved).unwrap();
    close(&db_key);
    db_service::load_kdbx(&saved, Some(PASSWORD), None).unwrap();
    assert_eq!(
        extra_fields(&form_json(&saved)),
        expected(),
        "после сохранения"
    );
    close(&saved);
}

#[test]
fn a_form_with_a_repeated_key_is_refused_and_a_renamed_one_is_saved() {
    let db_key = open_copy("edit.kdbx");
    let uuid = entry_uuid(&db_key);

    let form: EntryFormData = serde_json::from_value(form_json(&db_key)).unwrap();
    let refused = db_service::update_entry_from_form_data(&db_key, form);
    assert!(
        matches!(refused, Err(Error::DuplicateFieldKey)),
        "{:?}",
        refused
    );

    // Приложение переименовывает дубли - запись сохраняется, ничего не потеряно
    let mut v = form_json(&db_key);
    let mut seen = std::collections::HashSet::new();
    for f in v["fields"].as_array_mut().unwrap() {
        let key = f["key"].as_str().unwrap().to_string();
        if !seen.insert(key.clone()) {
            f["key"] = serde_json::json!(format!("{} 2", key));
        }
    }
    db_service::update_entry_from_form_data(&db_key, serde_json::from_value(v).unwrap()).unwrap();

    let after = db_service::get_entry_form_data_by_id(&db_key, &uuid).unwrap();
    let after = serde_json::to_value(&after).unwrap();
    assert_eq!(common::form::field(&after, "PIN"), Some("1111"));
    assert_eq!(common::form::field(&after, "PIN 2"), Some("2222"));
    assert_eq!(common::form::field(&after, "Note"), Some("first"));
    assert_eq!(common::form::field(&after, "Note 2"), Some("second"));
    close(&db_key);
}
