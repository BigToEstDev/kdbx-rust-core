//! Сохранение поверх существующего файла не должно оставлять хвост старого содержимого.
//!
//! Файлы открывались с `create(true)` без `truncate`: если новая база короче прежней, за её
//! концом оставались старые зашифрованные блоки. Round-trip этого не видит — ридер
//! останавливается на блоке нулевой длины и хвост игнорирует, база открывается. Поэтому тесты
//! сравнивают размер: файл, перезаписанный на месте, должен совпасть с тем же содержимым,
//! записанным в новый файл.
//!
//! Чтобы база реально уменьшилась, её создают с большим несжимаемым именем, а перед
//! сохранением меняют имя на короткое.

mod common;

use onekeepass_core::db_service::{self, DbSettings, Error, NewDatabase};

const PASSWORD: &str = "save-truncates-1234";
// Несжимаемое имя такого размера делает старый файл заметно больше нового
const BIG_NAME_LEN: usize = 256 * 1024;
const SHORT_NAME: &str = "Short";

fn temp_path(name: &str, ext: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "okp_save_truncates_{}_{}.{}",
        name,
        std::process::id(),
        ext
    ));
    p.to_str().unwrap().to_string()
}

// Псевдослучайные буквы и цифры (xorshift): gzip их почти не сжимает
fn incompressible_name(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHABET[(x % ALPHABET.len() as u64) as usize] as char
        })
        .collect()
}

// KDF уменьшен, чтобы тест был быстрым в debug; на размер файла он не влияет
fn new_db(db_key: &str) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!(incompressible_name(BIG_NAME_LEN));
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    serde_json::from_value(v).unwrap()
}

// Создаёт большую базу на диске и уменьшает её содержимое в памяти.
// Возвращает размер большого файла.
fn create_big_then_shrink(db_key: &str) -> u64 {
    common::init();
    let _ = std::fs::remove_file(db_key);
    db_service::create_kdbx(new_db(db_key)).unwrap();
    let big_len = file_len(db_key);

    let mut v = serde_json::to_value(db_service::get_db_settings(db_key).unwrap()).unwrap();
    v["meta"]["database_name"] = serde_json::json!(SHORT_NAME);
    let settings: DbSettings = serde_json::from_value(v).unwrap();
    db_service::set_db_settings(db_key, settings).unwrap();

    big_len
}

// Размер того же содержимого, записанного в файл, которого ещё нет
fn fresh_len(db_key: &str, name: &str) -> u64 {
    let fresh = temp_path(name, "fresh.kdbx");
    let _ = std::fs::remove_file(&fresh);
    db_service::save_to_db_file(db_key, &fresh).unwrap();
    let len = file_len(&fresh);
    let _ = std::fs::remove_file(&fresh);
    len
}

fn file_len(path: &str) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

fn assert_no_tail(path: &str, expected_len: u64, big_len: u64) {
    assert!(
        expected_len < big_len,
        "база не уменьшилась ({} >= {}) — тест ничего не проверяет",
        expected_len,
        big_len
    );
    assert_eq!(
        file_len(path),
        expected_len,
        "{}: после перезаписи остался хвост старого содержимого",
        path
    );
}

fn cleanup(db_key: &str, paths: &[&str]) {
    let _ = db_service::close_kdbx(db_key);
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
}

// Обычное сохранение без backup: write_kdbx_file(overwrite = false)
#[test]
fn save_in_place_truncates_db_file() {
    let db_key = temp_path("in_place", "kdbx");
    let big_len = create_big_then_shrink(&db_key);
    let expected = fresh_len(&db_key, "in_place");

    db_service::save_kdbx_with_backup(&db_key, None, false).unwrap();

    assert_no_tail(&db_key, expected, big_len);
    db_service::close_kdbx(&db_key).unwrap();
    db_service::load_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    cleanup(&db_key, &[&db_key]);
}

// Сохранение через backup: backup переиспользуется, затем копируется в базу целиком
#[test]
fn save_with_backup_truncates_backup_and_db_file() {
    let db_key = temp_path("backup", "kdbx");
    let backup = temp_path("backup", "bak.kdbx");
    let big_len = create_big_then_shrink(&db_key);
    // backup от прошлого сохранения — большой
    std::fs::copy(&db_key, &backup).unwrap();
    let expected = fresh_len(&db_key, "backup");

    db_service::save_kdbx_with_backup(&db_key, Some(&backup), false).unwrap();

    assert_no_tail(&backup, expected, big_len);
    assert_no_tail(&db_key, expected, big_len);
    cleanup(&db_key, &[&db_key, &backup]);
}

// Сохранение в указанный существующий файл: write_kdbx_content_to_file
#[test]
fn save_to_existing_file_truncates_it() {
    let db_key = temp_path("to_file", "kdbx");
    let target = temp_path("to_file", "target.kdbx");
    let big_len = create_big_then_shrink(&db_key);
    std::fs::copy(&db_key, &target).unwrap();
    let expected = fresh_len(&db_key, "to_file");

    db_service::save_to_db_file(&db_key, &target).unwrap();

    assert_no_tail(&target, expected, big_len);
    cleanup(&db_key, &[&db_key, &target]);
}

// "Сохранить как" поверх существующего файла: write_kdbx_file(overwrite = true)
#[test]
fn save_as_over_existing_file_truncates_it() {
    let db_key = temp_path("save_as", "kdbx");
    let target = temp_path("save_as", "target.kdbx");
    let big_len = create_big_then_shrink(&db_key);
    std::fs::copy(&db_key, &target).unwrap();
    let expected = fresh_len(&db_key, "save_as");

    // После save_as db_key базы становится путём нового файла
    db_service::save_as_kdbx(&db_key, &target).unwrap();

    assert_no_tail(&target, expected, big_len);
    cleanup(&target, &[&db_key, &target]);
}

// Генерация ключевого файла поверх существующего молча уничтожала старый ключ — база,
// закрытая им, больше не открывалась. Теперь существующий файл не трогается, решение
// о перезаписи — за UI.
#[test]
fn generate_key_file_refuses_to_overwrite_existing_file() {
    common::init();
    let key_file = temp_path("key_exists", "keyx");
    let old_key = b"existing key file content that must survive";
    std::fs::write(&key_file, old_key).unwrap();

    let result = db_service::generate_key_file(&key_file);

    let kind = match result {
        Err(Error::Io(e)) => e.kind(),
        other => panic!("ожидалась ошибка ввода-вывода, получено {:?}", other),
    };
    let content = std::fs::read(&key_file).unwrap();
    let _ = std::fs::remove_file(&key_file);
    assert_eq!(kind, std::io::ErrorKind::AlreadyExists);
    assert_eq!(content, old_key, "существующий ключевой файл изменён");
}

#[test]
fn generate_key_file_creates_new_file() {
    common::init();
    let key_file = temp_path("key_new", "keyx");
    let _ = std::fs::remove_file(&key_file);

    db_service::generate_key_file(&key_file).unwrap();

    let content = std::fs::read_to_string(&key_file).unwrap();
    let _ = std::fs::remove_file(&key_file);
    assert!(content.contains("<KeyFile>"), "не XML-ключ: {}", content);
}
