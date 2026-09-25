//! Чтение баз KDBX4, собранных СТОРОННЕЙ реализацией (pykeepass).
//!
//! Остальные интеграционные тесты создают базу нашим же кодом, поэтому проверяют
//! только round-trip: симметричная ошибка в шифровании/KDF осталась бы незамеченной.
//! Фикстуры здесь сгенерированы чужим кодом (tools/kdbx-oracle/gen_fixtures.py),
//! поэтому они проверяют совместимость с форматом, а не с самими собой.
//!
//! Фикстуры read-only: перед открытием копируются в temp dir, оригиналы в
//! tests/resources/ не изменяются.

mod common;

use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, EntryCategory};

const PASSWORD: &str = "test-pass-1234";

const ATTACHMENT_NAME: &str = "notes.txt";
const ATTACHMENT_DATA: &[u8] = b"example doc\n2 lines\n";
const TOTP_URL: &str =
    "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30";

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

// Копирует фикстуру (и key-file, если есть) в temp dir и возвращает путь к копии,
// который служит db_key. Так оригинал в репозитории остаётся неизменным.
//
// Счётчик нужен, потому что cargo гоняет тесты параллельно, а одну и ту же фикстуру
// открывает несколько тестов: без него копии дерутся за одно имя файла.
static COPY_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_copy(name: &str) -> String {
    let seq = COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_fixture_{}_{}_{}",
        std::process::id(),
        seq,
        name
    ));
    std::fs::copy(resource(name), &target).unwrap();
    target.to_str().unwrap().to_string()
}

fn open_fixture(name: &str, key_file: Option<&str>) -> String {
    common::init();

    let db_key = temp_copy(name);
    let key_file_copy = key_file.map(temp_copy);

    let loaded = db_service::load_kdbx(&db_key, Some(PASSWORD), key_file_copy.as_deref());
    assert!(
        loaded.is_ok(),
        "не удалось открыть фикстуру {}: {:?}",
        name,
        loaded.err()
    );
    db_key
}

fn close_fixture(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

// Все фикстуры имеют одинаковое содержимое (см. gen_fixtures.py), поэтому проверка общая.
fn verify_content(db_key: &str) {
    // --- группы: Root + подгруппа Work ---
    let tree = db_service::groups_summary_data(db_key).unwrap();
    let tree_json = serde_json::to_value(&tree).unwrap();
    let group_names: Vec<String> = tree_json["groups"]
        .as_object()
        .unwrap()
        .values()
        .filter_map(|g| g["name"].as_str().map(String::from))
        .collect();
    assert!(
        group_names.iter().any(|n| n == "Work"),
        "подгруппа Work не найдена, есть только: {:?}",
        group_names
    );

    // --- записи: GitHub, Email, Server ---
    let entries = db_service::entry_summary_data(db_key, EntryCategory::AllEntries).unwrap();
    let mut titles: Vec<String> = entries.iter().filter_map(|e| e.title.clone()).collect();
    titles.sort();
    assert_eq!(
        titles,
        vec!["Email", "GitHub", "Server"],
        "состав записей не совпал"
    );

    let server = entries
        .iter()
        .find(|e| e.title.as_deref() == Some("Server"))
        .expect("запись Server не найдена");
    let server_uuid = uuid::Uuid::parse_str(&server.uuid).unwrap();

    // --- protected-значения: пароль расшифрован inner-stream шифром ---
    let fields = db_service::entry_key_value_fields(db_key, &server_uuid).unwrap();
    let password = fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("password"))
        .map(|(_, v)| v.clone())
        .expect("поле Password отсутствует");
    assert_eq!(password, "srv-secret-3", "пароль расшифрован неверно");

    // TOTP тоже protected-значение и лежит в кастомном поле 'otp'
    let otp = fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("otp"))
        .map(|(_, v)| v.clone())
        .expect("поле otp отсутствует");
    assert_eq!(otp, TOTP_URL, "otp-url прочитан неверно");

    // --- аттачмент: имя, размер и байты ---
    let form = db_service::get_entry_form_data_by_id(db_key, &server_uuid).unwrap();
    let form_json = serde_json::to_value(&form).unwrap();
    let binaries = form_json["binary_key_values"].as_array().unwrap();
    assert_eq!(binaries.len(), 1, "ожидался один аттачмент");

    let binary = &binaries[0];
    assert_eq!(binary["key"].as_str(), Some(ATTACHMENT_NAME));
    assert_eq!(
        binary["data_size"].as_u64(),
        Some(ATTACHMENT_DATA.len() as u64)
    );

    // data_hash сериализуется как строка (см. util::from_or_to::string)
    let data_hash: u64 = binary["data_hash"].as_str().unwrap().parse().unwrap();
    let out_path = db_service::save_attachment_as_temp_file(
        db_key,
        &format!(
            "okp_fixture_attach_{}.bin",
            COPY_SEQ.fetch_add(1, Ordering::Relaxed)
        ),
        &data_hash,
    )
    .unwrap();
    let mut bytes = vec![];
    std::fs::File::open(&out_path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let _ = std::fs::remove_file(&out_path);
    assert_eq!(bytes, ATTACHMENT_DATA, "байты аттачмента не совпали");
}

#[test]
fn read_foreign_aes256_argon2d() {
    let db_key = open_fixture("aes256_argon2d.kdbx", None);
    verify_content(&db_key);
    close_fixture(&db_key);
}

#[test]
fn read_foreign_chacha20_argon2id() {
    let db_key = open_fixture("chacha20_argon2id.kdbx", None);
    verify_content(&db_key);
    close_fixture(&db_key);
}

#[test]
fn read_foreign_aes256_argon2d_with_key_file() {
    let db_key = open_fixture(
        "aes256_argon2d_keyfile.kdbx",
        Some("aes256_argon2d_keyfile.keyx"),
    );
    verify_content(&db_key);
    close_fixture(&db_key);
}

// Боевые параметры Argon2 (64 MB / 10 iter) — проверяем, что читаются и такие,
// не только заниженные тестовые.
#[test]
fn read_foreign_aes256_argon2d_prod_kdf_params() {
    let db_key = open_fixture("aes256_argon2d_prod_params.kdbx", None);
    verify_content(&db_key);
    close_fixture(&db_key);
}

#[test]
fn foreign_fixture_wrong_password_is_rejected() {
    common::init();

    let db_key = temp_copy("aes256_argon2d.kdbx");
    let loaded = db_service::load_kdbx(&db_key, Some("wrong-password"), None);
    assert!(loaded.is_err(), "неверный пароль должен отклоняться");
    let _ = std::fs::remove_file(&db_key);
}

// Key-file обязателен: с одним паролем эта база открываться не должна.
#[test]
fn foreign_fixture_key_file_is_required() {
    common::init();

    let db_key = temp_copy("aes256_argon2d_keyfile.kdbx");
    let loaded = db_service::load_kdbx(&db_key, Some(PASSWORD), None);
    assert!(
        loaded.is_err(),
        "база с key-file не должна открываться по одному паролю"
    );
    let _ = std::fs::remove_file(&db_key);
}
