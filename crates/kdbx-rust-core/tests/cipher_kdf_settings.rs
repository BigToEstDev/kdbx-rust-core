//! Шифр и KDF меняются в настройках базы (Step 68).
//!
//! Экран «Безопасность» меняет шифр (AES-256 / ChaCha20), вариант Argon2 (id / d) и число проходов через
//! `set_db_settings` и сразу сохраняет файл. Здесь — что всё это доходит до файла: после сохранения и
//! переоткрытия тем же паролем настройки — новые. Что заголовок записан новыми — сверяет pykeepass
//! (`verify_roundtrip.py`, база `written_aes256_argon2d_changed_to_chacha20_argon2id`).

mod common;

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, NewDatabase};

const PASSWORD: &str = "test-pass-1234";

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

/// Открытая база с паролем, шифром и KDF — как её создаёт приложение
fn open_new(db_key: &str, cipher_id: &str, algorithm: &str) {
    common::init();
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("CipherKdf");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["cipher_id"] = serde_json::json!(cipher_id);
    v["kdf"] = serde_json::json!({
        "algorithm": algorithm,
        "memory": 1048576,
        "iterations": 1,
        "parallelism": 1
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();

    db_service::create_and_write_to_writer(&mut Cursor::new(Vec::new()), new_db, None).unwrap();
}

fn settings(db_key: &str) -> serde_json::Value {
    serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap()
}

/// Меняет шифр, вариант Argon2 и проходы, сохраняет и открывает базу заново тем же паролем
fn change_save_and_reopen(db_key: &str, cipher_id: &str, algorithm: &str, iterations: u64) {
    let mut changed = settings(db_key);
    changed["cipher_id"] = serde_json::json!(cipher_id);
    changed["kdf"]["algorithm"] = serde_json::json!(algorithm);
    changed["kdf"]["iterations"] = serde_json::json!(iterations);
    db_service::set_db_settings(db_key, serde_json::from_value(changed).unwrap(), None).unwrap();

    let mut file = Cursor::new(Vec::new());
    db_service::save_kdbx_to_writer(&mut file, db_key).unwrap();
    db_service::close_kdbx(db_key).unwrap();

    db_service::read_kdbx(
        &mut Cursor::new(file.into_inner()),
        db_key,
        Some(PASSWORD),
        None,
        Some("cipher_kdf.kdbx"),
    )
    .unwrap();
}

#[test]
fn aes_and_argon2d_change_to_chacha20_and_argon2id() {
    let db_key = db_key("to_chacha20.kdbx");
    open_new(&db_key, "Aes256", "Argon2d");

    change_save_and_reopen(&db_key, "ChaCha20", "Argon2id", 4);

    let reopened = settings(&db_key);
    assert_eq!(reopened["cipher_id"], "ChaCha20");
    assert_eq!(reopened["kdf"]["algorithm"], "Argon2id");
    assert_eq!(reopened["kdf"]["iterations"], 4);
    // Память и параллелизм экран не меняет — остаются от создания
    assert_eq!(reopened["kdf"]["memory"], 1048576);
    assert_eq!(reopened["kdf"]["parallelism"], 1);
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn chacha20_and_argon2id_change_back_to_aes_and_argon2d() {
    let db_key = db_key("to_aes.kdbx");
    open_new(&db_key, "ChaCha20", "Argon2id");

    change_save_and_reopen(&db_key, "Aes256", "Argon2d", 3);

    let reopened = settings(&db_key);
    assert_eq!(reopened["cipher_id"], "Aes256");
    assert_eq!(reopened["kdf"]["algorithm"], "Argon2d");
    assert_eq!(reopened["kdf"]["iterations"], 3);
    db_service::close_kdbx(&db_key).unwrap();
}
