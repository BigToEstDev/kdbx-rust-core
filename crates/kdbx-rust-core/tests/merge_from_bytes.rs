//! Слияние копии и импорт другой базы — из байтов, со своими учётными данными (Step 106).
//!
//! Фикстуры собраны pykeepass (`gen_fixtures.py`, `build_merge_fixtures`): `merge_base.kdbx`, её копия
//! `merge_copy.kdbx` с другим паролем (правка записи с версией, удаление с `DeletedObject`, новая запись) и
//! другая база `merge_other.kdbx` со своим корнем. Правила слияния — как в KeePass, их точные тесты —
//! `db_merge::merge_tests`; здесь — весь путь на чужих файлах: открыть, слить, сохранить, открыть снова.

mod common;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, EntryCategory, Error};
use uuid::Uuid;

const PASSWORD: &str = "test-pass-1234";
const COPY_PASSWORD: &str = "copy-pass-5678";
const OTHER_PASSWORD: &str = "other-pass-9012";

const EDITED: &str = "6c3d9a10-0000-4000-8000-000000000002";
const DELETED: &str = "6c3d9a10-0000-4000-8000-000000000003";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

fn temp_path(suffix: &str) -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "okp_bytes_merge_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    path.to_str().unwrap().to_string()
}

/// Исходная база, открытая из своей копии во временной папке.
fn open_base() -> String {
    common::init();
    let path = temp_path("base.kdbx");
    std::fs::copy(resource("merge_base.kdbx"), &path).unwrap();
    db_service::load_kdbx(&path, Some(PASSWORD), None).unwrap();
    path
}

fn bytes_of(name: &str) -> Cursor<Vec<u8>> {
    Cursor::new(std::fs::read(resource(name)).unwrap())
}

fn close(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

fn titles(db_key: &str) -> Vec<String> {
    db_service::entry_summary_data(db_key, EntryCategory::AllEntries)
        .unwrap()
        .into_iter()
        .filter_map(|entry| entry.title)
        .collect()
}

fn password_of(db_key: &str, uuid: &str) -> String {
    let form =
        db_service::get_entry_form_data_by_id(db_key, &Uuid::parse_str(uuid).unwrap()).unwrap();
    let form = serde_json::to_value(form).unwrap();
    form["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|field| field["key"] == "Password")
        .and_then(|field| field["value"].as_str())
        .unwrap()
        .to_string()
}

#[test]
fn a_copy_with_another_password_brings_its_edit_its_deletion_and_its_new_entry() {
    let db_key = open_base();

    let result = db_service::merge_kdbx_from_bytes(
        &db_key,
        &mut bytes_of("merge_copy.kdbx"),
        Some(COPY_PASSWORD),
        None,
    )
    .unwrap();
    let result = serde_json::to_value(result).unwrap();
    assert_eq!(result["different_databases"], false, "{}", result);

    assert_eq!(titles(&db_key), vec!["Added", "Edited", "Kept"]);
    assert_eq!(
        password_of(&db_key, EDITED),
        "new-secret",
        "the newer edit wins"
    );
    let history =
        db_service::history_entries_summary(&db_key, &Uuid::parse_str(EDITED).unwrap()).unwrap();
    assert_eq!(history.len(), 1, "the version of the copy came along");
    assert!(
        db_service::get_entry_form_data_by_id(&db_key, &Uuid::parse_str(DELETED).unwrap()).is_err(),
        "deleted in the copy after its last edit here - deleted here too"
    );

    // Saved and read again - with the password of this database, not the copy's
    let saved = temp_path("merged.kdbx");
    db_service::save_to_db_file(&db_key, &saved).unwrap();
    close(&db_key);
    db_service::load_kdbx(&saved, Some(PASSWORD), None).unwrap();
    assert_eq!(titles(&saved), vec!["Added", "Edited", "Kept"]);
    assert_eq!(password_of(&saved, EDITED), "new-secret");
    close(&saved);
}

#[test]
fn a_different_database_is_imported_whole() {
    let db_key = open_base();

    let result = db_service::import_kdbx_from_bytes(
        &db_key,
        &mut bytes_of("merge_other.kdbx"),
        Some(OTHER_PASSWORD),
        None,
    )
    .unwrap();
    let result = serde_json::to_value(result).unwrap();
    assert_eq!(result["different_databases"], true, "{}", result);
    assert_eq!(
        titles(&db_key),
        vec!["Deleted", "Edited", "Foreign", "Kept"]
    );

    close(&db_key);
}

#[test]
fn the_wrong_operation_changes_nothing() {
    let db_key = open_base();

    let refused = db_service::merge_kdbx_from_bytes(
        &db_key,
        &mut bytes_of("merge_other.kdbx"),
        Some(OTHER_PASSWORD),
        None,
    );
    assert!(
        matches!(refused, Err(Error::NotSameDatabase)),
        "{:?}",
        refused
    );

    let refused = db_service::import_kdbx_from_bytes(
        &db_key,
        &mut bytes_of("merge_copy.kdbx"),
        Some(COPY_PASSWORD),
        None,
    );
    assert!(matches!(refused, Err(Error::SameDatabase)), "{:?}", refused);

    assert_eq!(titles(&db_key), vec!["Deleted", "Edited", "Kept"]);
    close(&db_key);
}

#[test]
fn a_copy_is_not_opened_with_the_password_of_this_database() {
    let db_key = open_base();

    let refused = db_service::merge_kdbx_from_bytes(
        &db_key,
        &mut bytes_of("merge_copy.kdbx"),
        Some(PASSWORD),
        None,
    );
    assert!(
        matches!(refused, Err(Error::InvalidCredentials)),
        "{:?}",
        refused
    );
    assert_eq!(titles(&db_key), vec!["Deleted", "Edited", "Kept"]);

    close(&db_key);
}
