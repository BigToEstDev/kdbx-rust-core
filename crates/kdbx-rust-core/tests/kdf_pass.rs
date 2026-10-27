//! Замер одного прохода KDF открытой базы (Step 68).
//!
//! Экран «Безопасность» показывает время открытия базы на этом телефоне: один проход, замеренный при
//! открытии экрана, × число проходов на барабане. Замер идёт с памятью и параллелизмом самой базы, а
//! её настройки не меняет.

mod common;

use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, Error, NewDatabase};

const PASSWORD: &str = "test-pass-1234";

const MEMORY_1_MIB: u64 = 1024 * 1024;
const MEMORY_64_MIB: u64 = 64 * 1024 * 1024;

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

/// Открытая база с паролем и заданными параметрами KDF — как её создаёт приложение
fn open_new(db_key: &str, algorithm: &str, memory: u64, iterations: u64) {
    common::init();
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("KdfPass");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({
        "algorithm": algorithm,
        "memory": memory,
        "iterations": iterations,
        "parallelism": 2
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();

    db_service::create_and_write_to_writer(&mut Cursor::new(Vec::new()), new_db, None).unwrap();
}

fn kdf_settings(db_key: &str) -> serde_json::Value {
    serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap()["kdf"].clone()
}

#[test]
fn a_pass_is_measured_and_the_kdf_of_the_database_stays_as_is() {
    let db_key = db_key("measured.kdbx");
    open_new(&db_key, "Argon2id", MEMORY_1_MIB, 7);
    let before = kdf_settings(&db_key);

    db_service::measure_kdf_pass(&db_key).unwrap();

    assert_eq!(kdf_settings(&db_key), before);
    assert_eq!(before["iterations"], 7);
    db_service::close_kdbx(&db_key).unwrap();
}

// Проход считается с памятью базы, а не с умолчаниями: в 64 раза больше памяти — дольше
#[test]
fn the_pass_takes_the_memory_of_the_database() {
    let small = db_key("small.kdbx");
    let large = db_key("large.kdbx");
    open_new(&small, "Argon2d", MEMORY_1_MIB, 1);
    open_new(&large, "Argon2d", MEMORY_64_MIB, 1);

    let small_pass = db_service::measure_kdf_pass(&small).unwrap();
    let large_pass = db_service::measure_kdf_pass(&large).unwrap();

    assert!(
        large_pass > small_pass,
        "64 MiB: {large_pass:?}, 1 MiB: {small_pass:?}"
    );
    db_service::close_kdbx(&small).unwrap();
    db_service::close_kdbx(&large).unwrap();
}

#[test]
fn a_locked_database_is_measured_and_stays_locked() {
    let db_key = db_key("locked.kdbx");
    open_new(&db_key, "Argon2id", MEMORY_1_MIB, 1);
    db_service::lock_kdbx(&db_key).unwrap();

    db_service::measure_kdf_pass(&db_key).unwrap();
    assert!(db_service::is_db_locked(&db_key).unwrap());

    db_service::unlock_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_database_that_is_not_open_is_not_found() {
    common::init();
    assert!(matches!(
        db_service::measure_kdf_pass(&db_key("never_opened.kdbx")),
        Err(Error::DbKeyNotFound)
    ));
}
