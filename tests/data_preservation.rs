//! Сохранность чужих данных при удалении кода (Step 13).
//!
//! Step 13 вырезает из ядра КОД passkey, SFTP/WebDAV-подключений и AutoOpen,
//! но НЕ поддержку их в формате: записи таких типов, созданные OneKeePass или
//! KeePassXC, обязаны читаться и переживать сохранение без потерь. Иначе
//! пользователь открывает свою базу нашим приложением, сохраняет — и теряет
//! данные, которых наш UI даже не показывает.
//!
//! Фикстура `okp_entry_types.kdbx` собрана сторонней реализацией
//! (tools/kdbx-oracle/gen_fixtures.py), поэтому проверяет формат, а не
//! round-trip нашего кода с самим собой.
//!
//! Тест обязан быть зелёным и ДО удалений, и ПОСЛЕ них.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use onekeepass_core::db_service::{self, EntryCategory};

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "okp_entry_types.kdbx";

// Поля passkey в формате KeePassXC: ядро их не интерпретирует, но обязано хранить.
const PASSKEY_FIELDS: &[(&str, &str)] = &[
    ("KPEX_PASSKEY_USERNAME", "octocat"),
    ("KPEX_PASSKEY_RELYING_PARTY", "github.com"),
    ("KPEX_PASSKEY_USER_HANDLE", "dXNlci1oYW5kbGUtMQ"),
    ("KPEX_PASSKEY_CREDENTIAL_ID", "Y3JlZC1pZC0x"),
    (
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "fake-pkcs8-private-key-for-tests",
    ),
];

// Типы записей OneKeePass: имя типа берётся из CustomData записи (OKP_K3).
const TYPED_ENTRIES: &[(&str, &str)] = &[
    ("Work DB", "Auto Database Open"),
    ("My SFTP", "SFTP Connection"),
    ("My WebDAV", "WebDAV Connection"),
];

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
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_preserve_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    target.to_str().unwrap().to_string()
}

fn open_copy(name: &str) -> String {
    common::init();
    let db_key = temp_path(name);
    std::fs::copy(resource(name), &db_key).unwrap();
    db_service::load_kdbx(&db_key, Some(PASSWORD), None)
        .unwrap_or_else(|e| panic!("не удалось открыть фикстуру {}: {:?}", name, e));
    db_key
}

fn open_existing(db_key: &str) {
    db_service::load_kdbx(db_key, Some(PASSWORD), None)
        .unwrap_or_else(|e| panic!("не удалось открыть сохранённый файл {}: {:?}", db_key, e));
}

fn close(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

fn entry_uuid(db_key: &str, title: &str) -> uuid::Uuid {
    let entries = db_service::entry_summary_data(db_key, EntryCategory::AllEntries).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.title.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("запись {} не найдена", title));
    uuid::Uuid::parse_str(&entry.uuid).unwrap()
}

/// Всё, что должно пережить и чтение, и сохранение нашим ядром.
fn verify_all(db_key: &str, stage: &str) {
    // --- группы AutoOpen и Connections ---
    let tree = db_service::groups_summary_data(db_key).unwrap();
    let tree_json = serde_json::to_value(&tree).unwrap();
    let group_names: Vec<String> = tree_json["groups"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|g| g["name"].as_str().map(String::from))
        .collect();
    for expected in ["AutoOpen", "Connections"] {
        assert!(
            group_names.iter().any(|n| n == expected),
            "[{}] группа {} потеряна, есть: {:?}",
            stage,
            expected,
            group_names
        );
    }

    // --- состав записей ---
    let entries = db_service::entry_summary_data(db_key, EntryCategory::AllEntries).unwrap();
    let mut titles: Vec<String> = entries.iter().filter_map(|e| e.title.clone()).collect();
    titles.sort();
    assert_eq!(
        titles,
        vec!["My SFTP", "My WebDAV", "Passkey Site", "Work DB"],
        "[{}] состав записей изменился",
        stage
    );

    // --- поля passkey, включая protected приватный ключ ---
    let passkey_uuid = entry_uuid(db_key, "Passkey Site");
    let fields = db_service::entry_key_value_fields(db_key, &passkey_uuid).unwrap();
    for (key, expected) in PASSKEY_FIELDS {
        let actual = fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("[{}] поле passkey {} потеряно", stage, key));
        assert_eq!(
            actual, *expected,
            "[{}] значение поля {} изменилось",
            stage, key
        );
    }

    // --- типы записей OneKeePass (CustomData OKP_K3) ---
    for (title, type_name) in TYPED_ENTRIES {
        let uuid = entry_uuid(db_key, title);
        let form = db_service::get_entry_form_data_by_id(db_key, &uuid).unwrap();
        let form_json = serde_json::to_value(&form).unwrap();
        assert_eq!(
            form_json["entry_type_name"].as_str(),
            Some(*type_name),
            "[{}] тип записи {} не распознан",
            stage,
            title
        );
    }

    // --- поля записей подключений и AutoOpen ---
    let sftp_uuid = entry_uuid(db_key, "My SFTP");
    let sftp_fields = db_service::entry_key_value_fields(db_key, &sftp_uuid).unwrap();
    for (key, expected) in [
        ("Host", "sftp.example.com"),
        ("Port", "22"),
        ("Start Dir", "/home/sftpuser"),
        ("Password", "sftp-secret-3"),
    ] {
        let actual = sftp_fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("[{}] поле SFTP {} потеряно", stage, key));
        assert_eq!(actual, expected, "[{}] поле SFTP {} изменилось", stage, key);
    }

    let auto_uuid = entry_uuid(db_key, "Work DB");
    let auto_fields = db_service::entry_key_value_fields(db_key, &auto_uuid).unwrap();
    for (key, expected) in [("URL", "kdbx://work.kdbx"), ("IfDevice", "laptop")] {
        let actual = auto_fields
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("[{}] поле AutoOpen {} потеряно", stage, key));
        assert_eq!(
            actual, expected,
            "[{}] поле AutoOpen {} изменилось",
            stage, key
        );
    }
}

/// Чтение чужой базы: всё на месте сразу после открытия.
#[test]
fn foreign_okp_types_are_read() {
    let db_key = open_copy(FIXTURE);
    verify_all(&db_key, "после чтения");
    close(&db_key);
}

/// Главная проверка степа: сохранение нашим ядром ничего не теряет.
#[test]
fn foreign_okp_types_survive_save() {
    let db_key = open_copy(FIXTURE);
    verify_all(&db_key, "после чтения");

    let saved = temp_path("saved.kdbx");
    db_service::save_to_db_file(&db_key, &saved).expect("сохранение в новый файл не удалось");
    close(&db_key);

    open_existing(&saved);
    verify_all(&saved, "после сохранения");
    close(&saved);
}
