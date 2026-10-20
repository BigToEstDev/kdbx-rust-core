//! Проверка пароля открытой базы и признак «из чего ключ» (Step 60).
//!
//! Включая биометрию из настроек, приложение просит пароль заново и сверяет его, прежде чем сохранить:
//! открывать базу второй раз не нужно — ядро держит хеш пароля отдельно от хеша key-файла, и пароль
//! сверяется один, key-файл у приложения не спрашивается. Базе без пароля биометрию не предлагают —
//! это говорит `credentials_used`.

mod common;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, CredentialsUsed, Error, FileKey, NewDatabase};

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

fn new_db(db_key: &str, password: Option<&str>) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("VerifyPassword");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(password);
    serde_json::from_value(v).unwrap()
}

fn key(name: &str, content: &[u8]) -> Option<FileKey> {
    Some(FileKey::from_bytes(name, content).unwrap())
}

/// Создаёт базу, как это делает приложение, и открывает её снова — с теми же учётными данными
fn open(db_key: &str, password: Option<&str>, key_file: Option<&[u8]>) {
    let mut out = Cursor::new(Vec::new());
    let file_key = key_file.and_then(|k| key("new.keyx", k));
    db_service::create_and_write_to_writer(&mut out, new_db(db_key, password), file_key).unwrap();
    db_service::close_kdbx(db_key).unwrap();

    let file_key = key_file.and_then(|k| key("new.keyx", k));
    db_service::read_kdbx(
        &mut Cursor::new(out.into_inner()),
        db_key,
        password,
        file_key,
        Some("test.kdbx"),
    )
    .unwrap();
}

#[test]
fn the_password_of_the_database_matches_another_one_does_not() {
    common::init();
    let db_key = db_key("password.kdbx");
    open(&db_key, Some(PASSWORD), None);

    assert!(db_service::verify_password(&db_key, PASSWORD).unwrap());
    assert!(!db_service::verify_password(&db_key, "test-pass-1235").unwrap());
    assert!(!db_service::verify_password(&db_key, "").unwrap());
    assert_eq!(
        db_service::credentials_used(&db_key).unwrap(),
        CredentialsUsed {
            password: true,
            key_file: false
        }
    );
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn with_a_key_file_too_the_password_matches_alone() {
    common::init();
    let db_key = db_key("aes256_argon2d_keyfile.kdbx");
    let bytes = std::fs::read(resource("aes256_argon2d_keyfile.kdbx")).unwrap();
    let key_file = std::fs::read(resource("aes256_argon2d_keyfile.keyx")).unwrap();
    db_service::read_kdbx(
        &mut Cursor::new(bytes),
        &db_key,
        Some(PASSWORD),
        key("aes256_argon2d_keyfile.keyx", &key_file),
        Some("aes256_argon2d_keyfile.kdbx"),
    )
    .unwrap();

    assert!(db_service::verify_password(&db_key, PASSWORD).unwrap());
    assert!(!db_service::verify_password(&db_key, "wrong").unwrap());
    assert_eq!(
        db_service::credentials_used(&db_key).unwrap(),
        CredentialsUsed {
            password: true,
            key_file: true
        }
    );
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_database_with_only_a_key_file_matches_no_password() {
    common::init();
    let db_key = db_key("key_only.kdbx");
    open(
        &db_key,
        None,
        Some(b"any file can be a key, a photo for one"),
    );

    assert!(!db_service::verify_password(&db_key, PASSWORD).unwrap());
    assert!(!db_service::verify_password(&db_key, "").unwrap());
    assert_eq!(
        db_service::credentials_used(&db_key).unwrap(),
        CredentialsUsed {
            password: false,
            key_file: true
        }
    );
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_locked_database_is_checked_and_stays_locked() {
    common::init();
    let db_key = db_key("locked.kdbx");
    open(&db_key, Some(PASSWORD), None);
    db_service::lock_kdbx(&db_key).unwrap();

    assert!(db_service::verify_password(&db_key, PASSWORD).unwrap());
    assert!(!db_service::verify_password(&db_key, "wrong").unwrap());
    assert!(db_service::is_db_locked(&db_key).unwrap());

    db_service::unlock_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_database_that_is_not_open_is_not_found() {
    common::init();
    let db_key = db_key("never_opened.kdbx");

    assert!(matches!(
        db_service::verify_password(&db_key, PASSWORD),
        Err(Error::DbKeyNotFound)
    ));
    assert!(matches!(
        db_service::credentials_used(&db_key),
        Err(Error::DbKeyNotFound)
    ));
}
