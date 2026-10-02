//! Key-файл байтами и лимиты учётных данных (Step 29).
//!
//! На Android у key-файла нет пути, который ядро могло бы открыть: он за SAF. Поэтому мобильный путь
//! ядра — создание, открытие и разблокировка — принимает его байтами, как и саму базу. Здесь
//! проверяется, что байты дают тот же ключ, что и путь, и что лимиты длины пароля и размера key-файла
//! срабатывают там, где задуманы, и не срабатывают там, где запрещены (открытие чужой базы).

mod common;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{
    self, Error, FileKey, NewDatabase, KEY_FILE_MAX_SIZE, PASSWORD_MAX_CHARS,
};

const PASSWORD: &str = "test-pass-1234";

// Значение продублировано в tools/kdbx-oracle/gen_fixtures.py (LONG_PASSWORD) — менять вместе
fn long_password() -> String {
    "x".repeat(300) + "-пароль-😀"
}

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
    v["database_name"] = serde_json::json!("KeyFileBytes");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(password);
    serde_json::from_value(v).unwrap()
}

fn key(name: &str, content: &[u8]) -> Option<FileKey> {
    Some(FileKey::from_bytes(name, content).unwrap())
}

/// Создаёт базу, как это делает приложение, и возвращает её байты
fn create(db_key: &str, password: Option<&str>, file_key: Option<FileKey>) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    db_service::create_and_write_to_writer(&mut out, new_db(db_key, password), file_key).unwrap();
    db_service::close_kdbx(db_key).unwrap();
    out.into_inner()
}

fn read(
    db_key: &str,
    bytes: &[u8],
    password: Option<&str>,
    file_key: Option<FileKey>,
) -> db_service::Result<db_service::KdbxLoaded> {
    db_service::read_kdbx(
        &mut Cursor::new(bytes.to_vec()),
        db_key,
        password,
        file_key,
        Some("test.kdbx"),
    )
}

#[test]
fn a_database_created_with_a_key_file_as_bytes_opens_with_the_same_bytes() {
    common::init();
    let db_key = db_key("created.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();

    let bytes = create(&db_key, Some(PASSWORD), key("new.keyx", &key_file));

    let loaded = read(&db_key, &bytes, Some(PASSWORD), key("new.keyx", &key_file)).unwrap();
    assert_eq!(loaded.key_file_name.as_deref(), Some("new.keyx"));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn the_name_of_the_key_file_does_not_matter_only_its_content() {
    common::init();
    let db_key = db_key("renamed.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();

    let bytes = create(&db_key, Some(PASSWORD), key("new.keyx", &key_file));

    let loaded = read(&db_key, &bytes, Some(PASSWORD), key("copy.keyx", &key_file)).unwrap();
    assert_eq!(loaded.key_file_name.as_deref(), Some("copy.keyx"));
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_database_with_a_key_file_does_not_open_without_it_or_with_another_one() {
    common::init();
    let db_key = db_key("guarded.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    let other = FileKey::generate_xml_key_file().unwrap();

    let bytes = create(&db_key, Some(PASSWORD), key("new.keyx", &key_file));

    assert!(matches!(
        read(&db_key, &bytes, Some(PASSWORD), None),
        Err(Error::HeaderHmacHashCheckFailed)
    ));
    assert!(matches!(
        read(&db_key, &bytes, Some(PASSWORD), key("other.keyx", &other)),
        Err(Error::HeaderHmacHashCheckFailed)
    ));
}

#[test]
fn a_database_with_only_a_key_file_opens_with_it() {
    common::init();
    let db_key = db_key("key_only.kdbx");
    let key_file = b"any file can be a key, a photo for one";

    let bytes = create(&db_key, None, key("photo.jpg", key_file));

    read(&db_key, &bytes, None, key("photo.jpg", key_file)).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn unlock_takes_the_key_file_as_bytes() {
    common::init();
    let db_key = db_key("locked.kdbx");
    let key_file = FileKey::generate_xml_key_file().unwrap();
    let other = FileKey::generate_xml_key_file().unwrap();

    let bytes = create(&db_key, Some(PASSWORD), key("new.keyx", &key_file));
    read(&db_key, &bytes, Some(PASSWORD), key("new.keyx", &key_file)).unwrap();
    db_service::lock_kdbx(&db_key).unwrap();

    assert!(matches!(
        db_service::unlock_kdbx(&db_key, Some(PASSWORD), key("other.keyx", &other)),
        Err(Error::HeaderHmacHashCheckFailed)
    ));
    assert!(matches!(
        db_service::unlock_kdbx(&db_key, Some(PASSWORD), None),
        Err(Error::HeaderHmacHashCheckFailed)
    ));
    assert!(db_service::is_db_locked(&db_key).unwrap());

    db_service::unlock_kdbx(&db_key, Some(PASSWORD), key("new.keyx", &key_file)).unwrap();
    assert!(!db_service::is_db_locked(&db_key).unwrap());
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_key_file_of_a_foreign_database_opens_as_bytes() {
    common::init();
    let db_key = db_key("aes256_argon2d_keyfile.kdbx");
    let bytes = std::fs::read(resource("aes256_argon2d_keyfile.kdbx")).unwrap();
    let key_file = std::fs::read(resource("aes256_argon2d_keyfile.keyx")).unwrap();

    read(
        &db_key,
        &bytes,
        Some(PASSWORD),
        key("aes256_argon2d_keyfile.keyx", &key_file),
    )
    .unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_key_file_path_is_refused_when_creating_from_bytes() {
    common::init();
    let db_key = db_key("path.kdbx");
    let mut v = serde_json::to_value(new_db(&db_key, Some(PASSWORD))).unwrap();
    v["key_file_name"] = serde_json::json!("/data/user/0/app/files/key.keyx");
    let with_path: NewDatabase = serde_json::from_value(v).unwrap();

    let result =
        db_service::create_and_write_to_writer(&mut Cursor::new(Vec::new()), with_path, None);

    assert!(matches!(result, Err(Error::DataError(_))));
    assert!(!db_service::is_db_opened(&db_key));
}

#[test]
fn a_key_file_over_the_limit_is_refused() {
    let content = vec![0u8; KEY_FILE_MAX_SIZE as usize + 1];
    assert!(matches!(
        FileKey::from_bytes("video.mp4", &content),
        Err(Error::KeyFileTooLarge)
    ));
}

#[test]
fn a_password_over_the_limit_cannot_be_set_on_creating() {
    common::init();
    let db_key = db_key("too_long.kdbx");
    let password = "a".repeat(PASSWORD_MAX_CHARS + 1);

    let result = db_service::create_and_write_to_writer(
        &mut Cursor::new(Vec::new()),
        new_db(&db_key, Some(&password)),
        None,
    );

    assert!(matches!(result, Err(Error::PasswordTooLong)));
    assert!(!db_service::is_db_opened(&db_key));
}

#[test]
fn a_password_of_the_limit_in_characters_can_be_set() {
    common::init();
    let db_key = db_key("of_limit.kdbx");
    // 256 символов, но 1024 байта в utf-8
    let password = "😀".repeat(PASSWORD_MAX_CHARS);

    let bytes = create(&db_key, Some(&password), None);

    read(&db_key, &bytes, Some(&password), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_password_over_the_limit_cannot_be_set_in_settings_and_nothing_changes() {
    common::init();
    let db_key = db_key("settings.kdbx");
    let bytes = create(&db_key, Some(PASSWORD), None);
    read(&db_key, &bytes, Some(PASSWORD), None).unwrap();

    let mut v = serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();
    v["password"] = serde_json::json!("a".repeat(PASSWORD_MAX_CHARS + 1));
    v["password_used"] = serde_json::json!(true);
    v["password_changed"] = serde_json::json!(true);
    v["meta"]["database_name"] = serde_json::json!("Renamed");
    let settings = serde_json::from_value(v).unwrap();

    assert!(matches!(
        db_service::set_db_settings(&db_key, settings, None),
        Err(Error::PasswordTooLong)
    ));

    // Ни имя, ни пароль не тронуты: база запирается и отпирается старым паролем
    let after = db_service::get_db_settings(&db_key).unwrap();
    assert_eq!(after.get_database_name(), "KeyFileBytes");
    db_service::lock_kdbx(&db_key).unwrap();
    db_service::unlock_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}

#[test]
fn a_foreign_database_with_a_longer_password_still_opens_and_unlocks() {
    common::init();
    let db_key = db_key("long_password.kdbx");
    let bytes = std::fs::read(resource("long_password.kdbx")).unwrap();
    let password = long_password();
    assert!(password.chars().count() > PASSWORD_MAX_CHARS);

    read(&db_key, &bytes, Some(&password), None).unwrap();
    db_service::lock_kdbx(&db_key).unwrap();
    db_service::unlock_kdbx(&db_key, Some(&password), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
}
