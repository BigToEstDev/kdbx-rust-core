//! Версия формата файла и сжатие — через настройки базы (Step 64).
//!
//! Клиент видит в `get_db_settings`, каким KDBX файл прочитан (ядро читает 4.0 и 4.1, пишет всегда 4.1), и
//! какое у него сжатие; сжатие меняет `set_db_settings`, и оно доходит до заголовка файла.

mod common;

use std::path::PathBuf;

use kdbx_rust_core::db_service::{self, Compression, KdbxVersion};

// Фикстура pykeepass: KDBX 4.0 со сжатием GZip
const FIXTURE_40: &str = "aes256_argon2d.kdbx";
const FIXTURE_41: &str = "all_fields_41.kdbx";
const PASSWORD: &str = "test-pass-1234";

/// Поле `CompressionFlags` внешнего заголовка.
const COMPRESSION_FLAGS: u8 = 3;

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

/// Копия фикстуры во временном файле, открытая: ключ базы — путь к копии.
fn open_copy(fixture: &str, name: &str) -> String {
    common::init();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "okp_file_format_{}_{}.kdbx",
        name,
        std::process::id()
    ));
    std::fs::copy(resource(fixture), &path).unwrap();
    let db_key = path.to_str().unwrap().to_string();
    db_service::load_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_key
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

/// Версия из сигнатуры файла — байты 8..12.
fn file_version(db_key: &str) -> u32 {
    let bytes = std::fs::read(db_key).unwrap();
    u32::from_le_bytes(bytes[8..12].try_into().unwrap())
}

/// Флаг сжатия из заголовка самого файла: поля TLV после 12 байт сигнатур.
fn file_compression_flag(db_key: &str) -> u32 {
    let bytes = std::fs::read(db_key).unwrap();
    let mut pos = 12;
    loop {
        let kind = bytes[pos];
        let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap()) as usize;
        if kind == COMPRESSION_FLAGS {
            return u32::from_le_bytes(bytes[pos + 5..pos + 9].try_into().unwrap());
        }
        assert_ne!(kind, 0, "в заголовке нет флага сжатия");
        pos += 5 + len;
    }
}

fn set_compression(db_key: &str, compression: Compression) {
    let mut settings = db_service::get_db_settings(db_key).unwrap();
    settings.set_compression(compression);
    db_service::set_db_settings(db_key, settings, None).unwrap();
}

#[test]
fn a_file_of_kdbx_4_0_is_said_to_be_4_0_until_it_is_saved() {
    let db_key = open_copy(FIXTURE_40, "v40");
    assert_eq!(
        file_version(&db_key),
        0x0004_0000,
        "фикстура должна быть 4.0"
    );

    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().kdbx_version(),
        KdbxVersion::V40
    );

    db_service::save_kdbx_with_backup(&db_key, None, false).unwrap();
    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().kdbx_version(),
        KdbxVersion::V41
    );
    assert_eq!(file_version(&db_key), 0x0004_0001);

    cleanup(&db_key);
}

#[test]
fn a_file_of_kdbx_4_1_is_said_to_be_4_1() {
    let db_key = open_copy(FIXTURE_41, "v41");

    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().kdbx_version(),
        KdbxVersion::V41
    );

    cleanup(&db_key);
}

#[test]
fn the_version_sent_back_is_not_read() {
    let db_key = open_copy(FIXTURE_40, "v_ignored");

    let mut v = serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();
    v["kdbx_version"] = serde_json::json!("4.1");
    db_service::set_db_settings(&db_key, serde_json::from_value(v).unwrap(), None).unwrap();

    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().kdbx_version(),
        KdbxVersion::V40
    );

    cleanup(&db_key);
}

#[test]
fn the_compression_of_the_file_is_what_the_settings_say() {
    let db_key = open_copy(FIXTURE_40, "gzip");

    assert_eq!(file_compression_flag(&db_key), 1);
    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().compression(),
        Compression::GZip
    );

    cleanup(&db_key);
}

#[test]
fn compression_switched_off_reaches_the_file_and_survives_reopening() {
    let db_key = open_copy(FIXTURE_40, "none");

    set_compression(&db_key, Compression::None);
    save_and_reopen(&db_key);

    assert_eq!(file_compression_flag(&db_key), 0);
    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().compression(),
        Compression::None
    );

    cleanup(&db_key);
}

#[test]
fn compression_switched_back_on_reaches_the_file() {
    let db_key = open_copy(FIXTURE_40, "back");

    set_compression(&db_key, Compression::None);
    save_and_reopen(&db_key);
    set_compression(&db_key, Compression::GZip);
    save_and_reopen(&db_key);

    assert_eq!(file_compression_flag(&db_key), 1);
    assert_eq!(
        db_service::get_db_settings(&db_key).unwrap().compression(),
        Compression::GZip
    );

    cleanup(&db_key);
}

#[test]
fn the_content_survives_a_file_without_compression() {
    let db_key = open_copy(FIXTURE_41, "content");
    let before =
        db_service::entry_summary_data(&db_key, db_service::EntryCategory::AllEntries).unwrap();

    set_compression(&db_key, Compression::None);
    save_and_reopen(&db_key);

    let after =
        db_service::entry_summary_data(&db_key, db_service::EntryCategory::AllEntries).unwrap();
    assert_eq!(
        serde_json::to_value(&before).unwrap(),
        serde_json::to_value(&after).unwrap()
    );

    cleanup(&db_key);
}
