//! Слияние копии и импорт другой базы — из байтов, со своими учётными данными (Step 106).
//!
//! Фикстуры собраны pykeepass (`gen_fixtures.py`, `build_merge_fixtures`): `merge_base.kdbx`, её копия
//! `merge_copy.kdbx` с другим паролем (правка записи с версией, удаление с `DeletedObject`, новая запись) и
//! другая база `merge_other.kdbx` со своим корнем. Правила слияния — как в KeePass, их точные тесты —
//! `db_merge::merge_tests`; здесь — весь путь на чужих файлах: открыть, слить, сохранить, открыть снова.
//! В обе стороны (Step 109, `merge_kdbx_both_ways`) — байты для файла копии: её пароль, шифр и KDF, новые seed.

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

// --- В обе стороны (Step 109): слить копию и получить байты для её файла ---

/// Поля внешнего заголовка KDBX 4: id → значение (подпись и версия — 12 байт, затем id u8, длина u32 LE).
fn header_fields(bytes: &[u8]) -> std::collections::HashMap<u8, Vec<u8>> {
    let mut fields = std::collections::HashMap::new();
    let mut at = 12;
    loop {
        let id = bytes[at];
        let len = u32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
        fields.insert(id, bytes[at + 5..at + 5 + len].to_vec());
        at += 5 + len;
        if id == 0 {
            return fields;
        }
    }
}

const CIPHER_ID: u8 = 2;
const MASTER_SEED: u8 = 4;
const ENCRYPTION_IV: u8 = 7;
const KDF_PARAMETERS: u8 = 11;

fn settings(db_key: &str) -> serde_json::Value {
    serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap()
}

/// Открытая база с другими шифром и KDF, чем у копии, — чтобы было видно, чей заголовок у байтов копии.
fn open_base_with_its_own_header() -> String {
    let db_key = open_base();
    let mut changed = settings(&db_key);
    changed["cipher_id"] = serde_json::json!("ChaCha20");
    changed["kdf"]["algorithm"] = serde_json::json!("Argon2d");
    changed["kdf"]["iterations"] = serde_json::json!(2);
    db_service::set_db_settings(&db_key, serde_json::from_value(changed).unwrap(), None).unwrap();
    db_key
}

fn merge_both_ways(db_key: &str) -> db_service::MergedBothWays {
    db_service::merge_kdbx_both_ways(
        db_key,
        &mut bytes_of("merge_copy.kdbx"),
        Some(COPY_PASSWORD),
        None,
    )
    .unwrap()
}

/// Байты копии — файлом во временной папке, открытым её паролем.
fn open_copy(bytes: &[u8]) -> String {
    let path = temp_path("copy.kdbx");
    std::fs::write(&path, bytes).unwrap();
    db_service::load_kdbx(&path, Some(COPY_PASSWORD), None).unwrap();
    path
}

#[test]
fn both_ways_the_copy_gets_the_merged_database_under_its_own_password() {
    let db_key = open_base();

    let merged = merge_both_ways(&db_key);
    let result = serde_json::to_value(&merged.result).unwrap();
    assert_eq!(result["different_databases"], false, "{}", result);
    assert_eq!(titles(&db_key), vec!["Added", "Edited", "Kept"]);

    let refused = {
        let path = temp_path("copy_wrong.kdbx");
        std::fs::write(&path, &merged.copy).unwrap();
        let refused = db_service::load_kdbx(&path, Some(PASSWORD), None);
        let _ = std::fs::remove_file(&path);
        refused
    };
    assert!(
        matches!(refused, Err(Error::InvalidCredentials)),
        "the copy keeps its own password, not this one's: {:?}",
        refused.map(|_| ())
    );

    let copy = open_copy(&merged.copy);
    assert_eq!(titles(&copy), vec!["Added", "Edited", "Kept"]);
    assert_eq!(password_of(&copy, EDITED), "new-secret");
    assert!(
        db_service::get_entry_form_data_by_id(&copy, &Uuid::parse_str(DELETED).unwrap()).is_err()
    );
    close(&copy);
    close(&db_key);
}

#[test]
fn both_ways_the_copy_keeps_its_cipher_and_kdf_with_fresh_seeds() {
    let db_key = open_base_with_its_own_header();
    let original = std::fs::read(resource("merge_copy.kdbx")).unwrap();

    let merged = merge_both_ways(&db_key);

    let before = header_fields(&original);
    let after = header_fields(&merged.copy);
    assert_eq!(
        after[&CIPHER_ID], before[&CIPHER_ID],
        "the cipher of the copy"
    );
    assert_ne!(
        after[&MASTER_SEED], before[&MASTER_SEED],
        "a fresh master seed"
    );
    assert_ne!(after[&ENCRYPTION_IV], before[&ENCRYPTION_IV], "a fresh iv");
    assert_ne!(
        after[&KDF_PARAMETERS], before[&KDF_PARAMETERS],
        "a fresh salt"
    );

    let copy = open_copy(&merged.copy);
    let copy_settings = settings(&copy);
    assert_ne!(
        copy_settings["cipher_id"], "ChaCha20",
        "not the cipher of this database"
    );
    assert_ne!(copy_settings["kdf"]["algorithm"], "Argon2d");
    close(&copy);

    let fixture = temp_path("copy_fixture.kdbx");
    std::fs::write(&fixture, &original).unwrap();
    db_service::load_kdbx(&fixture, Some(COPY_PASSWORD), None).unwrap();
    assert_eq!(copy_settings["cipher_id"], settings(&fixture)["cipher_id"]);
    assert_eq!(copy_settings["kdf"], settings(&fixture)["kdf"]);
    close(&fixture);
    close(&db_key);
}

#[test]
fn both_ways_the_copy_gets_the_attachments_of_this_database() {
    let db_key = open_base();
    let kept = Uuid::parse_str("6c3d9a10-0000-4000-8000-000000000001").unwrap();
    let form = db_service::get_entry_form_data_by_id(&db_key, &kept).unwrap();
    db_service::update_entry_from_form_data_with_attachments(
        &db_key,
        form,
        &[db_service::NewAttachment {
            name: "note.txt".into(),
            size: 5,
        }],
        b"hello".to_vec(),
    )
    .unwrap();

    let merged = merge_both_ways(&db_key);

    let copy = open_copy(&merged.copy);
    let form =
        serde_json::to_value(db_service::get_entry_form_data_by_id(&copy, &kept).unwrap()).unwrap();
    let attachment = &form["binary_key_values"][0];
    assert_eq!(attachment["key"], "note.txt");
    let hash: u64 = attachment["data_hash"].as_str().unwrap().parse().unwrap();
    let mut out = vec![];
    db_service::save_attachment_to_writer(&copy, &hash, &mut out).unwrap();
    assert_eq!(out, b"hello");
    close(&copy);
    close(&db_key);
}

#[test]
fn both_ways_the_bytes_come_even_when_nothing_changed_here() {
    let db_key = open_base();
    merge_both_ways(&db_key);

    // The second time the copy brings nothing new - its bytes are still there, merged
    let merged = merge_both_ways(&db_key);
    let result = serde_json::to_value(&merged.result).unwrap();
    assert_eq!(result["added_entries"], serde_json::json!([]), "{}", result);
    let copy = open_copy(&merged.copy);
    assert_eq!(titles(&copy), vec!["Added", "Edited", "Kept"]);
    close(&copy);
    close(&db_key);
}

#[test]
fn both_ways_keeps_the_checksum_of_the_open_file() {
    let db_key = open_base();
    let before = db_service::db_checksum_hash(&db_key).unwrap();

    merge_both_ways(&db_key);

    assert_eq!(
        db_service::db_checksum_hash(&db_key).unwrap(),
        before,
        "the bytes are for another file - the open one is unchanged"
    );
    close(&db_key);
}

#[test]
fn both_ways_refuses_a_different_database_and_a_locked_one() {
    let db_key = open_base();

    let refused = db_service::merge_kdbx_both_ways(
        &db_key,
        &mut bytes_of("merge_other.kdbx"),
        Some(OTHER_PASSWORD),
        None,
    );
    assert!(
        matches!(refused, Err(Error::NotSameDatabase)),
        "{:?}",
        refused.map(|_| ())
    );
    assert_eq!(titles(&db_key), vec!["Deleted", "Edited", "Kept"]);

    db_service::lock_kdbx(&db_key).unwrap();
    let refused = db_service::merge_kdbx_both_ways(
        &db_key,
        &mut bytes_of("merge_copy.kdbx"),
        Some(COPY_PASSWORD),
        None,
    );
    assert!(
        matches!(refused, Err(Error::DbLocked)),
        "{:?}",
        refused.map(|_| ())
    );
    close(&db_key);
}
