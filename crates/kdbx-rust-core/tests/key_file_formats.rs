//! Key-файлы всех форматов, что читают KeePass / KeePassXC (Step 113).
//!
//! Базы и key-файлы собраны pykeepass (`tools/kdbx-oracle/gen_fixtures.py`, `build_key_file_format_fixtures`) —
//! его разбор совпадает с KeePassXC (`src/keys/FileKey.cpp`): XML `<KeyFile>` 1.0 (base64) и 2.0 (hex), объявление
//! не обязательно; XML не `<KeyFile>` — как любой файл; ровно 32 байта — ключ как есть; ровно 64 hex — декодированные
//! 32 байта; остальное — SHA-256 всего файла. База, закрытая таким файлом на ПК, открывается у нас тем же файлом.

mod common;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, FileKey};

// Продублировано в gen_fixtures.py (PASSWORD) — менять вместе
const PASSWORD: &str = "test-pass-1234";

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

// Хранилище открытых баз в ядре общее на процесс, а тесты идут параллельно — у каждого свой db_key
static SEQ: AtomicU64 = AtomicU64::new(0);

fn db_key(name: &str) -> String {
    format!(
        "content://test/{}/{}/{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        name
    )
}

/// Открывает базу-фикстуру её key-файлом, байтами — как приложение
fn opens_with_its_key_file(database: &str, key_file: &str) {
    common::init();
    let db_key = db_key(database);
    let bytes = std::fs::read(resource(database)).unwrap();
    let content = std::fs::read(resource(key_file)).unwrap();
    let file_key = FileKey::from_bytes(key_file, &content).unwrap();

    db_service::read_kdbx(
        &mut Cursor::new(bytes),
        &db_key,
        Some(PASSWORD),
        Some(file_key),
        Some(database),
    )
    .unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_key_file_of_exactly_32_bytes_is_the_key_itself() {
    opens_with_its_key_file("key_file_raw32.kdbx", "key_file_raw32.key");
}

#[test]
fn a_key_file_of_exactly_64_hex_characters_is_the_key_decoded() {
    opens_with_its_key_file("key_file_hex64.kdbx", "key_file_hex64.key");
}

#[test]
fn an_xml_key_file_of_version_1_has_the_key_in_base64() {
    opens_with_its_key_file("key_file_xml_v1.kdbx", "key_file_xml_v1.key");
}

#[test]
fn an_xml_key_file_without_the_declaration_is_read_as_xml() {
    opens_with_its_key_file("key_file_xml_no_decl.kdbx", "key_file_xml_no_decl.keyx");
}

#[test]
fn an_xml_file_that_is_not_a_key_file_is_hashed_as_any_file() {
    opens_with_its_key_file("key_file_xml_other.kdbx", "key_file_xml_other.xml");
}
