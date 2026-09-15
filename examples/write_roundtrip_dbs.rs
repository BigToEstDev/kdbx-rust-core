//! Пишет базы KDBX4 нашим ядром — для проверки сторонней реализацией.
//!
//! Обратная сторона `tests/foreign_fixtures.rs`: там мы читаем чужие файлы, здесь
//! отдаём свои. Файлы проверяет `tools/kdbx-oracle/verify_roundtrip.py`, который и
//! запускает этот пример. Отдельная CI-job, не часть `cargo test`.
//!
//! Использование:
//!     cargo run --quiet --example write_roundtrip_dbs -- <выходная директория>

// Key store из интеграционных тестов. Логгер не включаем (только init_key_main_store):
// debug-логи ядра засоряли бы вывод и искажали замеры.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use onekeepass_core::db_content;
use onekeepass_core::db_service::{self, NewDatabase};
use uuid::Uuid;

// Значения должны совпадать с verify_roundtrip.py — он их проверяет
const PASSWORD: &str = "test-pass-1234";
const ATTACHMENT_NAME: &str = "notes.txt";
const ATTACHMENT_DATA: &[u8] = b"example doc\n2 lines\n";
const TOTP_URL: &str =
    "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30";

// NewDatabase собирается через serde: поля pub(crate), но структура Serialize/Deserialize.
// Так же поступают интеграционные тесты.
fn new_db(db_key: &str, cipher_id: &str, kdf: &str, key_file: Option<&str>) -> NewDatabase {
    let mut value = serde_json::to_value(NewDatabase::default()).unwrap();
    value["database_name"] = serde_json::json!("RoundTripDb");
    value["database_file_name"] = serde_json::json!(db_key);
    value["password"] = serde_json::json!(PASSWORD);
    value["cipher_id"] = serde_json::json!(cipher_id);
    // KdfAlgorithm сериализуется internally tagged: serde(tag = "algorithm"), см. db/mod.rs.
    // Остальные параметры Argon2 подставит Default — у Argon2Kdf есть serde(default)
    value["kdf"] = serde_json::json!({ "algorithm": kdf });
    if let Some(path) = key_file {
        value["key_file_name"] = serde_json::json!(path);
    }
    serde_json::from_value(value).unwrap()
}

fn add_entry(
    db_key: &str,
    parent_group_uuid: &Uuid,
    title: &str,
    username: &str,
    password: &str,
) -> Uuid {
    let login_type_uuid = db_content::standard_type_uuid_by_name("Login");
    let form =
        db_service::new_entry_form_data_by_id(db_key, login_type_uuid, Some(parent_group_uuid))
            .unwrap();

    let mut value = serde_json::to_value(&form).unwrap();
    let entry_uuid = value["uuid"].as_str().unwrap().to_string();
    value["title"] = serde_json::json!(title);

    let section = value["section_fields"]["Login Details"]
        .as_array_mut()
        .unwrap();
    for field in section.iter_mut() {
        match field["key"].as_str() {
            Some("UserName") => field["value"] = serde_json::json!(username),
            Some("Password") => field["value"] = serde_json::json!(password),
            _ => {}
        }
    }

    let form = serde_json::from_value(value).unwrap();
    db_service::insert_entry_from_form_data(db_key, form).unwrap();
    Uuid::parse_str(&entry_uuid).unwrap()
}

// TOTP в KeePass — обычное строковое поле otp с protected-значением.
// Новое поле собираем копией существующего Password-поля: у KeyValueData нет
// serde(default), поэтому объект целиком из литерала не соберётся.
fn add_totp_and_attachment(db_key: &str, entry_uuid: &Uuid, attachment_source: &str) {
    let info = db_service::upload_entry_attachment(db_key, attachment_source).unwrap();

    let form = db_service::get_entry_form_data_by_id(db_key, entry_uuid).unwrap();
    let mut value = serde_json::to_value(&form).unwrap();
    value["notes"] = serde_json::json!("roundtrip entry with attachment and totp");

    let section = value["section_fields"]["Login Details"]
        .as_array_mut()
        .unwrap();
    let mut otp_field = section
        .iter()
        .find(|f| f["key"].as_str() == Some("Password"))
        .cloned()
        .expect("поле Password не найдено");
    otp_field["key"] = serde_json::json!("otp");
    otp_field["value"] = serde_json::json!(TOTP_URL);
    otp_field["protected"] = serde_json::json!(true);
    otp_field["standard_field"] = serde_json::json!(false);
    otp_field["required"] = serde_json::json!(false);
    section.push(otp_field);

    // index_ref пересчитывается при записи по data_hash, поэтому здесь 0
    value["binary_key_values"] = serde_json::json!([{
        "key": ATTACHMENT_NAME,
        "value": "",
        "index_ref": 0,
        "data_hash": info.data_hash.to_string(),
        "data_size": info.data_size,
    }]);

    let form = serde_json::from_value(value).unwrap();
    db_service::update_entry_from_form_data(db_key, form).unwrap();
}

fn build_db(out_dir: &str, file_name: &str, cipher_id: &str, kdf: &str, with_key_file: bool) {
    let db_key = format!("{}/{}", out_dir, file_name);
    let _ = std::fs::remove_file(&db_key);

    let key_file = if with_key_file {
        let path = format!("{}.keyx", db_key.trim_end_matches(".kdbx"));
        let _ = std::fs::remove_file(&path);
        // Key-file пишет наше ядро — заодно проверяем, читает ли его сторонняя реализация
        db_service::generate_key_file(&path).unwrap();
        Some(path)
    } else {
        None
    };

    db_service::create_kdbx(new_db(&db_key, cipher_id, kdf, key_file.as_deref())).unwrap();

    let tree = db_service::groups_summary_data(&db_key).unwrap();
    let root_uuid = tree.root_uuid;

    add_entry(&db_key, &root_uuid, "GitHub", "octocat", "gh-secret-1");
    add_entry(&db_key, &root_uuid, "Email", "user@example.com", "mail-secret-2");

    // Второй аргумент — mark_as_category; имя задаётся отдельно, uuid читаем через serde
    // (поле pub(crate), а Group сериализуется)
    let mut work_group = db_service::new_blank_group_with_parent(root_uuid, false).unwrap();
    work_group.name = "Work".into();
    let work_uuid = Uuid::parse_str(
        serde_json::to_value(&work_group).unwrap()["uuid"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    db_service::insert_group(&db_key, work_group).unwrap();

    let server_uuid = add_entry(&db_key, &work_uuid, "Server", "admin", "srv-secret-3");

    let attachment_source = format!("{}/{}", out_dir, ATTACHMENT_NAME);
    std::fs::write(&attachment_source, ATTACHMENT_DATA).unwrap();
    add_totp_and_attachment(&db_key, &server_uuid, &attachment_source);

    db_service::save_kdbx_with_backup(&db_key, None, true).unwrap();
    db_service::close_kdbx(&db_key).unwrap();

    println!(
        "{}|{}|{}|{}",
        db_key,
        cipher_id,
        kdf,
        key_file.unwrap_or_default()
    );
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .expect("укажите выходную директорию для баз");
    std::fs::create_dir_all(&out_dir).unwrap();

    common::init_key_main_store();

    build_db(
        &out_dir,
        "written_aes256_argon2d.kdbx",
        "Aes256",
        "Argon2d",
        false,
    );
    build_db(
        &out_dir,
        "written_chacha20_argon2id.kdbx",
        "ChaCha20",
        "Argon2id",
        false,
    );
    build_db(
        &out_dir,
        "written_aes256_argon2d_keyfile.kdbx",
        "Aes256",
        "Argon2d",
        true,
    );
}
