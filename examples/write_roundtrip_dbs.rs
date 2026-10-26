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

use kdbx_rust_core::db_service::{self, Compression, NewDatabase};
use uuid::Uuid;

// Значения должны совпадать с verify_roundtrip.py — он их проверяет
const PASSWORD: &str = "test-pass-1234";
const ATTACHMENT_NAME: &str = "notes.txt";
const ATTACHMENT_DATA: &[u8] = b"example doc\n2 lines\n";
const TOTP_URL: &str =
    "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30";

// Скрытые поля новой базы, как у KeePass и KeePassXC; имена — как в `Meta/MemoryProtection` без `Protect`
const DEFAULT_PROTECTED: &[&str] = &["Password"];
// Имя в файле -> ключ формы настроек ядра
const PROTECTION_KEYS: &[(&str, &str)] = &[
    ("Title", "protect_title"),
    ("UserName", "protect_username"),
    ("Password", "protect_password"),
    ("URL", "protect_url"),
    ("Notes", "protect_notes"),
];

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
    let form = db_service::new_entry_form_data(Some(parent_group_uuid));

    let mut value = serde_json::to_value(&form).unwrap();
    let entry_uuid = value["uuid"].as_str().unwrap().to_string();
    common::form::set_field(&mut value, "Title", title);
    common::form::set_field(&mut value, "UserName", username);
    common::form::set_field(&mut value, "Password", password);

    let form = serde_json::from_value(value).unwrap();
    db_service::insert_entry_from_form_data(db_key, form).unwrap();
    Uuid::parse_str(&entry_uuid).unwrap()
}

const PHONE_FIELD: &str = "Phone";
const PHONE_VALUE: &str = "+7 900 000-00-00";

// TOTP в KeePass — обычное строковое поле otp с protected-значением.
fn add_totp_and_attachment(db_key: &str, entry_uuid: &Uuid, attachment_source: &str) {
    let info = db_service::upload_entry_attachment(db_key, attachment_source).unwrap();

    let form = db_service::get_entry_form_data_by_id(db_key, entry_uuid).unwrap();
    let mut value = serde_json::to_value(&form).unwrap();
    common::form::set_field(
        &mut value,
        "Notes",
        "roundtrip entry with attachment and totp",
    );
    common::form::set_field(&mut value, "otp", TOTP_URL);
    common::form::protect(&mut value, "otp");

    // Тип своего поля — в CustomData записи, ключ PassHolder.FieldTypes (Step 76)
    common::form::set_field(&mut value, PHONE_FIELD, PHONE_VALUE);
    let fields = value["fields"].as_array_mut().unwrap();
    let phone = fields.iter_mut().find(|f| f["key"] == PHONE_FIELD).unwrap();
    phone["field_type"] = serde_json::json!("phone");

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

#[derive(Clone, Copy, PartialEq)]
enum KeyFile {
    None,
    /// Ядро пишет key-файл само, по пути, и база создаётся по пути — desktop
    Path,
    /// Ядро отдаёт байты key-файла, пишет их вызывающий, база создаётся в буфер — так делает
    /// приложение на Android (Step 29)
    Bytes,
}

/// Что задаётся через настройки базы после создания — так, как это делает приложение
struct Settings<'a> {
    /// Новая база — GZip; другое сжатие — через настройки (Step 64)
    compression: Compression,
    /// Скрытые поля (Step 66)
    protected: &'a [&'a str],
    /// Шифр и KDF, с которыми база создаётся; в настройках меняются на заявленные (Step 68). `None` — сразу с ними
    created_as: Option<(&'a str, &'a str)>,
}

const DEFAULT_SETTINGS: Settings = Settings {
    compression: Compression::GZip,
    protected: DEFAULT_PROTECTED,
    created_as: None,
};

fn build_db(
    out_dir: &str,
    file_name: &str,
    cipher_id: &str,
    kdf: &str,
    key_file_kind: KeyFile,
    settings: Settings,
) {
    let Settings {
        compression,
        protected,
        created_as,
    } = settings;
    let (created_cipher, created_kdf) = created_as.unwrap_or((cipher_id, kdf));
    let db_key = format!("{}/{}", out_dir, file_name);
    let _ = std::fs::remove_file(&db_key);

    let key_file = if key_file_kind == KeyFile::None {
        None
    } else {
        let path = format!("{}.keyx", db_key.trim_end_matches(".kdbx"));
        let _ = std::fs::remove_file(&path);
        // Key-file генерирует наше ядро — заодно проверяем, читает ли его сторонняя реализация
        if key_file_kind == KeyFile::Path {
            db_service::generate_key_file(&path).unwrap();
        } else {
            std::fs::write(&path, db_service::generate_key_file_content().unwrap()).unwrap();
        }
        Some(path)
    };

    if key_file_kind == KeyFile::Bytes {
        let path = key_file.as_deref().unwrap();
        let file_key =
            db_service::FileKey::from_bytes("written_by_app.keyx", &std::fs::read(path).unwrap())
                .unwrap();
        let mut buffer = std::io::Cursor::new(Vec::new());
        db_service::create_and_write_to_writer(
            &mut buffer,
            new_db(&db_key, created_cipher, created_kdf, None),
            Some(file_key),
        )
        .unwrap();
        // Как приложение после создания: байты базы ложатся в файл. db_key здесь — путь, поэтому
        // дальше база правится и сохраняется тем же кодом, что и остальные
        std::fs::write(&db_key, buffer.into_inner()).unwrap();
    } else {
        db_service::create_kdbx(new_db(
            &db_key,
            created_cipher,
            created_kdf,
            key_file.as_deref(),
        ))
        .unwrap();
    }

    let tree = db_service::groups_summary_data(&db_key).unwrap();
    let root_uuid = tree.root_uuid;

    add_entry(&db_key, &root_uuid, "GitHub", "octocat", "gh-secret-1");
    add_entry(
        &db_key,
        &root_uuid,
        "Email",
        "user@example.com",
        "mail-secret-2",
    );

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

    // Удалённая запись: корзина и PreviousParentGroup (Step 69) должны читаться чужим кодом
    let trashed_uuid = add_entry(&db_key, &work_uuid, "Trashed", "old", "old-secret-4");
    db_service::delete_entry(&db_key, trashed_uuid).unwrap();

    // Новая база — GZip; другое сжатие — через настройки, как его задаёт приложение (Step 64)
    if compression != Compression::GZip {
        let mut settings = db_service::get_db_settings(&db_key).unwrap();
        settings.set_compression(compression);
        db_service::set_db_settings(&db_key, settings, None).unwrap();
    }

    // Скрытые поля — тоже через настройки, как приложение (Step 66); форма — через serde, поля pub(crate)
    if protected != DEFAULT_PROTECTED {
        let mut settings =
            serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();
        for (name, key) in PROTECTION_KEYS {
            settings["meta"]["memory_protection"][key] =
                serde_json::json!(protected.contains(name));
        }
        db_service::set_db_settings(&db_key, serde_json::from_value(settings).unwrap(), None)
            .unwrap();
    }

    // Шифр и вариант Argon2 — через настройки, как их меняет экран «Безопасность» (Step 68); параметры
    // Argon2 остаются от создания
    if created_as.is_some() {
        let mut settings =
            serde_json::to_value(db_service::get_db_settings(&db_key).unwrap()).unwrap();
        settings["cipher_id"] = serde_json::json!(cipher_id);
        settings["kdf"]["algorithm"] = serde_json::json!(kdf);
        db_service::set_db_settings(&db_key, serde_json::from_value(settings).unwrap(), None)
            .unwrap();
    }

    db_service::save_kdbx_with_backup(&db_key, None, true).unwrap();
    db_service::close_kdbx(&db_key).unwrap();

    println!(
        "{}|{}|{}|{}|{:?}|{}",
        db_key,
        cipher_id,
        kdf,
        key_file.unwrap_or_default(),
        compression,
        protected.join(",")
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
        KeyFile::None,
        DEFAULT_SETTINGS,
    );
    build_db(
        &out_dir,
        "written_chacha20_argon2id.kdbx",
        "ChaCha20",
        "Argon2id",
        KeyFile::None,
        DEFAULT_SETTINGS,
    );
    build_db(
        &out_dir,
        "written_aes256_argon2d_keyfile.kdbx",
        "Aes256",
        "Argon2d",
        KeyFile::Path,
        DEFAULT_SETTINGS,
    );
    build_db(
        &out_dir,
        "written_aes256_argon2id_keyfile_bytes.kdbx",
        "Aes256",
        "Argon2id",
        KeyFile::Bytes,
        DEFAULT_SETTINGS,
    );
    build_db(
        &out_dir,
        "written_chacha20_argon2id_uncompressed.kdbx",
        "ChaCha20",
        "Argon2id",
        KeyFile::None,
        Settings {
            compression: Compression::None,
            protected: &["Title", "URL", "Notes"],
            created_as: None,
        },
    );
    build_db(
        &out_dir,
        "written_aes256_argon2d_changed_to_chacha20_argon2id.kdbx",
        "ChaCha20",
        "Argon2id",
        KeyFile::None,
        Settings {
            created_as: Some(("Aes256", "Argon2d")),
            ..DEFAULT_SETTINGS
        },
    );
}
