//! Смена учётных данных через `set_db_settings`, key-файл содержимым (Step 31).
//!
//! До Step 31 `set_db_settings` открывал `DbSettings.key_file_name` как путь при **любом**
//! `key_file_used` — даже когда менялось одно название базы. После Step 29 там имя для показа, а не путь,
//! так что база с key-файлом не давала поменять в настройках ничего. Теперь key-файл приходит содержимым
//! рядом с настройками и только когда меняется; `key_file_name` на входе не читается.
//!
//! Каждая смена проверяется по-настоящему: база сохраняется в байты, закрывается и открывается заново —
//! старыми учётными данными не должна, новыми должна.

mod common;

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, DbSettings, Error, FileKey, NewDatabase};

const PASSWORD: &str = "test-pass-1234";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn db_key(name: &str) -> String {
    format!(
        "content://test/{}/{}/{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        name
    )
}

fn key(name: &str, content: &[u8]) -> Option<FileKey> {
    Some(FileKey::from_bytes(name, content).unwrap())
}

/// Открытая база с паролем и, если дан, key-файлом — как её создаёт приложение.
fn open_new(db_key: &str, key_file: Option<&[u8]>) {
    common::init();
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("Settings");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({"algorithm": "Argon2id", "memory": 1048576, "iterations": 1, "parallelism": 1});
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();

    db_service::create_and_write_to_writer(
        &mut Cursor::new(Vec::new()),
        new_db,
        key_file.and_then(|k| key("old.keyx", k)),
    )
    .unwrap();
}

/// Настройки, как их отдаёт ядро, с правкой поверх — так их правит экран.
fn settings_with(db_key: &str, edit: impl FnOnce(&mut serde_json::Value)) -> DbSettings {
    let mut v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    edit(&mut v);
    serde_json::from_value(v).unwrap()
}

/// Сохраняет, закрывает и пробует открыть заново — что на самом деле записалось в файл. Открылась — база
/// снова открыта в ядре под тем же ключом; нет — закрыта.
fn reopens_with(db_key: &str, password: Option<&str>, key_file: Option<&[u8]>) -> bool {
    let mut out = Cursor::new(Vec::new());
    db_service::save_kdbx_to_writer(&mut out, db_key).unwrap();
    db_service::close_kdbx(db_key).unwrap();

    db_service::read_kdbx(
        &mut Cursor::new(out.into_inner()),
        db_key,
        password,
        key_file.and_then(|k| key("any.keyx", k)),
        None,
    )
    .is_ok()
}

fn name_of(db_key: &str) -> String {
    db_service::get_db_settings(db_key)
        .unwrap()
        .get_database_name()
        .to_string()
}

#[test]
fn only_the_name_changes_in_a_database_with_a_key_file() {
    let db_key = db_key("rename.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&key_file));

    let settings = settings_with(&db_key, |v| v["meta"]["database_name"] = "Renamed".into());
    db_service::set_db_settings(&db_key, settings, None).unwrap();

    assert_eq!(name_of(&db_key), "Renamed");
    assert!(reopens_with(&db_key, Some(PASSWORD), Some(&key_file)));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn the_key_file_name_in_the_settings_is_not_opened() {
    let db_key = db_key("not-a-path.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&key_file));

    // Будь это поле путём, ядро пошло бы его открывать и упало бы
    let settings = settings_with(&db_key, |v| {
        v["key_file_name"] = "/no/such/dir/key.keyx".into();
        v["meta"]["database_name"] = "Renamed".into();
    });
    db_service::set_db_settings(&db_key, settings, None).unwrap();

    assert_eq!(name_of(&db_key), "Renamed");
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_new_key_file_replaces_the_old_one() {
    let db_key = db_key("new-key.kdbx");
    let old = FileKey::generate_xml_key_file().unwrap();
    let new = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&old));

    let settings = settings_with(&db_key, |v| v["key_file_changed"] = true.into());
    db_service::set_db_settings(&db_key, settings, key("new.keyx", &new)).unwrap();
    assert_eq!(
        db_service::get_db_settings(&db_key)
            .unwrap()
            .key_file_name(),
        Some("new.keyx")
    );

    // Старым — нет, новым — да
    let mut out = Cursor::new(Vec::new());
    db_service::save_kdbx_to_writer(&mut out, &db_key).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
    let bytes = out.into_inner();
    let read = |k: &[u8]| {
        db_service::read_kdbx(
            &mut Cursor::new(bytes.clone()),
            &db_key,
            Some(PASSWORD),
            key("k.keyx", k),
            None,
        )
    };
    assert!(matches!(read(&old), Err(Error::InvalidCredentials)));
    read(&new).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn the_same_key_file_under_another_name_is_not_a_change_of_the_key() {
    let db_key = db_key("same-key.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&key_file));

    let settings = settings_with(&db_key, |v| v["key_file_changed"] = true.into());
    db_service::set_db_settings(&db_key, settings, key("renamed.keyx", &key_file)).unwrap();

    // Имя для показа — новое, ключ — тот же
    assert_eq!(
        db_service::get_db_settings(&db_key)
            .unwrap()
            .key_file_name(),
        Some("renamed.keyx")
    );
    assert!(reopens_with(&db_key, Some(PASSWORD), Some(&key_file)));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_key_file_is_added_to_a_database_without_one() {
    let db_key = db_key("add-key.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, None);

    let settings = settings_with(&db_key, |v| {
        v["key_file_used"] = true.into();
        v["key_file_changed"] = true.into();
    });
    db_service::set_db_settings(&db_key, settings, key("added.keyx", &key_file)).unwrap();

    assert!(reopens_with(&db_key, Some(PASSWORD), Some(&key_file)));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn the_key_file_is_removed_and_the_password_alone_opens() {
    let db_key = db_key("remove-key.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&key_file));

    let settings = settings_with(&db_key, |v| {
        v["key_file_used"] = false.into();
        v["key_file_changed"] = true.into();
    });
    db_service::set_db_settings(&db_key, settings, None).unwrap();

    assert!(reopens_with(&db_key, Some(PASSWORD), None));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn both_factors_cannot_be_removed_and_nothing_changes() {
    let db_key = db_key("no-factors.kdbx");
    open_new(&db_key, None);

    let settings = settings_with(&db_key, |v| {
        v["password_used"] = false.into();
        v["password_changed"] = true.into();
        v["meta"]["database_name"] = "Renamed".into();
    });
    assert!(matches!(
        db_service::set_db_settings(&db_key, settings, None),
        Err(Error::InSufficientCredentials)
    ));

    assert_eq!(
        name_of(&db_key),
        "Settings",
        "refused before anything changed"
    );
    assert!(reopens_with(&db_key, Some(PASSWORD), None));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_key_file_passed_without_changing_it_is_refused_and_nothing_changes() {
    let db_key = db_key("unasked-key.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, None);

    let settings = settings_with(&db_key, |v| v["meta"]["database_name"] = "Renamed".into());
    assert!(matches!(
        db_service::set_db_settings(&db_key, settings, key("k.keyx", &key_file)),
        Err(Error::DataError(_))
    ));

    assert_eq!(name_of(&db_key), "Settings");
    assert!(reopens_with(&db_key, Some(PASSWORD), None));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn changing_the_key_file_without_one_is_refused() {
    let db_key = db_key("missing-key.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    open_new(&db_key, Some(&key_file));

    let settings = settings_with(&db_key, |v| v["key_file_changed"] = true.into());
    assert!(matches!(
        db_service::set_db_settings(&db_key, settings, None),
        Err(Error::DataError(_))
    ));

    assert!(reopens_with(&db_key, Some(PASSWORD), Some(&key_file)));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn an_unchanged_key_file_has_to_match_the_database() {
    let db_key = db_key("flag-mismatch.kdbx");
    open_new(&db_key, None);

    // «key-файл используется, но не меняется» — а у базы его нет
    let settings = settings_with(&db_key, |v| v["key_file_used"] = true.into());
    assert!(matches!(
        db_service::set_db_settings(&db_key, settings, None),
        Err(Error::DataError(_))
    ));
    db_service::close_kdbx(&db_key).unwrap();
}
