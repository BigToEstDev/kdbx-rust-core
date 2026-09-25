//! TOTP формата оригинального KeePass 2.47+ на фикстуре, собранной сторонней
//! реализацией (Step 21).
//!
//! `tests/resources/time_otp_41.kdbx` сгенерирована pykeepass-ом
//! (`tools/kdbx-oracle/gen_fixtures.py`): 2FA лежит в полях `TimeOtp-*`, секрет — в каждой из
//! четырёх допустимых кодировок. Настоящего KeePass под рукой не было, поэтому поля записаны по
//! документации формата: тесты проверяют наш разбор, запись и сохранность полей, но не
//! совместимость с самим KeePass.
//!
//! Фикстура read-only: перед открытием копируется в temp dir.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use onekeepass_core::db_service::{self, EntryCategory, OtpSettings};
use uuid::Uuid;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "time_otp_41.kdbx";

// Тестовый секрет RFC 6238 "12345678901234567890"
const SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SECRET_HEX: &str = "3132333435363738393031323334353637383930";

static COPY_SEQ: AtomicU64 = AtomicU64::new(0);

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

fn open_fixture() -> String {
    common::init();

    let seq = COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_time_otp_{}_{}_{}",
        std::process::id(),
        seq,
        FIXTURE
    ));
    std::fs::copy(resource(FIXTURE), &target).unwrap();
    let db_key = target.to_str().unwrap().to_string();

    db_service::load_kdbx(&db_key, Some(PASSWORD), None).expect("фикстура не открылась");
    db_key
}

fn close_fixture(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

fn reopen(db_key: &str) {
    db_service::save_kdbx_with_backup(db_key, None, false).expect("сохранение не удалось");
    db_service::close_kdbx(db_key).unwrap();
    db_service::load_kdbx(db_key, Some(PASSWORD), None).expect("база не перечиталась");
}

fn entry_uuid(db_key: &str, title: &str) -> Uuid {
    let entries = db_service::entry_summary_data(db_key, EntryCategory::AllEntries).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.title.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("запись {} не найдена", title));
    Uuid::parse_str(&entry.uuid).unwrap()
}

// Код и период по каждому полю записи, у которого ядро смогло посчитать токен
fn tokens(db_key: &str, title: &str) -> HashMap<String, (String, u64)> {
    let uuid = entry_uuid(db_key, title);
    let form_data = db_service::get_entry_form_data_by_id(db_key, &uuid).unwrap();
    let json = serde_json::to_value(&form_data).unwrap();

    json["section_fields"]
        .as_object()
        .expect("поля формы разложены по секциям")
        .values()
        .flat_map(|fields| fields.as_array().cloned().unwrap_or_default())
        .filter_map(|field| {
            let token = field.get("current_opt_token")?;
            if token.is_null() {
                return None;
            }
            Some((
                field["key"].as_str()?.to_string(),
                (
                    token["token"].as_str()?.to_string(),
                    token["period"].as_u64()?,
                ),
            ))
        })
        .collect()
}

fn field_values(db_key: &str, title: &str) -> HashMap<String, String> {
    let uuid = entry_uuid(db_key, title);
    db_service::entry_key_value_fields(db_key, &uuid).unwrap()
}

#[test]
fn every_secret_encoding_of_a_keepass_entry_gives_the_same_code() {
    let db_key = open_fixture();

    let mut codes = Vec::new();
    for (title, field) in [
        ("Base32 Secret", "TimeOtp-Secret-Base32"),
        ("Hex Secret", "TimeOtp-Secret-Hex"),
        ("Base64 Secret", "TimeOtp-Secret-Base64"),
        ("Plain Secret", "TimeOtp-Secret"),
    ] {
        let found = tokens(&db_key, title);
        let (token, period) = found
            .get(field)
            .unwrap_or_else(|| panic!("{}: нет кода по полю {}", title, field));
        assert_eq!(token.len(), 6, "{}", title);
        assert_eq!(*period, 30, "{}", title);
        codes.push(token.clone());
    }

    // Один и тот же секрет в четырёх записях: коды обязаны совпасть
    assert!(
        codes.windows(2).all(|w| w[0] == w[1]),
        "кодировки дали разные коды: {:?}",
        codes
    );

    close_fixture(&db_key);
}

#[test]
fn the_keepass_period_and_length_fields_are_applied() {
    let db_key = open_fixture();

    let found = tokens(&db_key, "All Parameters");
    let (token, period) = found
        .get("TimeOtp-Secret-Base32")
        .expect("нет кода у записи со всеми параметрами");
    assert_eq!(token.len(), 8, "TimeOtp-Length = 8");
    assert_eq!(*period, 60, "TimeOtp-Period = 60");

    close_fixture(&db_key);
}

#[test]
fn an_unreadable_secret_gives_no_code_and_survives_saving() {
    let db_key = open_fixture();

    assert!(
        tokens(&db_key, "Broken Secret").is_empty(),
        "нечитаемый секрет не должен давать код"
    );

    reopen(&db_key);
    assert_eq!(
        field_values(&db_key, "Broken Secret").get("TimeOtp-Secret-Base32"),
        Some(&"not base32 !!".to_string()),
        "поле испорчено при пересохранении"
    );

    close_fixture(&db_key);
}

#[test]
fn an_entry_with_both_formats_gives_a_code_for_each_field() {
    let db_key = open_fixture();

    let found = tokens(&db_key, "Both Formats");
    assert!(
        found.contains_key("otp"),
        "нет кода по полю otp: {:?}",
        found
    );
    assert!(
        found.contains_key("TimeOtp-Secret-Base32"),
        "нет кода по полю TimeOtp-Secret-Base32: {:?}",
        found
    );

    // В списке записей место только под один код — там выигрывает otp
    let uuid = entry_uuid(&db_key, "Both Formats");
    let list = db_service::entry_list_current_otps(&db_key, &[uuid]).unwrap();
    let row = list.first().expect("записи с 2FA нет в списке");
    assert_eq!(row.entry_uuid, uuid.to_string());
    assert_eq!(row.otp_field_name, "otp");

    close_fixture(&db_key);
}

#[test]
fn a_keepass_entry_keeps_its_format_through_a_save() {
    let db_key = open_fixture();
    let uuid = entry_uuid(&db_key, "Hex Secret");

    // Другой секрет, введённый пользователем у нас
    db_service::set_entry_otp(
        &db_key,
        &uuid,
        &OtpSettings {
            secret_or_url: SECRET_BASE32.to_string(),
            period: Some(45),
            digits: Some(7),
            hash_algorithm: None,
        },
    )
    .unwrap();

    reopen(&db_key);

    let values = field_values(&db_key, "Hex Secret");
    assert_eq!(
        values.get("TimeOtp-Secret-Hex"),
        Some(&SECRET_HEX.to_string()),
        "секрет должен остаться в hex, как в исходном файле"
    );
    assert!(
        !values.contains_key("otp"),
        "запись KeePass не должна превратиться в otpauth-url: {:?}",
        values
    );
    assert_eq!(values.get("TimeOtp-Period"), Some(&"45".to_string()));
    assert_eq!(values.get("TimeOtp-Length"), Some(&"7".to_string()));

    let found = tokens(&db_key, "Hex Secret");
    let (token, period) = found
        .get("TimeOtp-Secret-Hex")
        .expect("нет кода после записи");
    assert_eq!(token.len(), 7);
    assert_eq!(*period, 45);

    close_fixture(&db_key);
}

#[test]
fn removing_a_2fa_leaves_no_keepass_field_in_the_saved_file() {
    let db_key = open_fixture();
    let uuid = entry_uuid(&db_key, "All Parameters");

    db_service::delete_entry_otp(&db_key, &uuid).unwrap();
    reopen(&db_key);

    let values = field_values(&db_key, "All Parameters");
    for field in [
        "TimeOtp-Secret-Base32",
        "TimeOtp-Secret-Hex",
        "TimeOtp-Secret-Base64",
        "TimeOtp-Secret",
        "TimeOtp-Period",
        "TimeOtp-Length",
        "TimeOtp-Algorithm",
    ] {
        assert!(
            !values.contains_key(field),
            "{} остался в сохранённом файле",
            field
        );
    }
    assert!(tokens(&db_key, "All Parameters").is_empty());

    close_fixture(&db_key);
}
