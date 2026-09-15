//! KDF, выбранный клиентом при создании базы, должен попасть в файл.
//!
//! Клиент (UI, мобильное приложение) собирает `NewDatabase` через serde и указывает
//! только `algorithm`. Раньше вариант Argon2 брался из скрытого поля `Argon2Kdf.variant`
//! с serde(default) = Argon2d, поэтому `{"algorithm": "Argon2id"}` молча давал Argon2d.
//! Round-trip своим же кодом этого не видит: чтение берёт вариант из UUID в заголовке,
//! так что файл «Argon2d под видом Argon2id» открывается без ошибок. Поэтому тест
//! разбирает outer header записанного файла сам.

mod common;

use onekeepass_core::db_service::{self, NewDatabase};

const PASSWORD: &str = "kdf-written-1234";

// UUID KDF из спецификации KDBX4 (KeePassLib/Cryptography/KeyDerivation/Argon2Kdf.cs)
const ARGON2_D_UUID: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
const ARGON2_ID_UUID: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];

// Outer header KDBX4: 12 байт сигнатур/версии, затем поля [id: u8][len: u32 LE][data]
const HEADER_START: usize = 12;
const FIELD_END_OF_HEADER: u8 = 0;
const FIELD_KDF_PARAMETERS: u8 = 11;
// VariantDictionary: [version: u16], затем [type: u8][key_len: u32][key][val_len: u32][val]
const VARIANT_DICT_START: usize = 2;
const VARIANT_END: u8 = 0;
const KDF_UUID_KEY: &[u8] = b"$UUID";

fn read_u32(data: &[u8], pos: usize) -> usize {
    u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize
}

fn kdf_parameters(file: &[u8]) -> &[u8] {
    let mut pos = HEADER_START;
    loop {
        let id = file[pos];
        let len = read_u32(file, pos + 1);
        let data = &file[pos + 5..pos + 5 + len];
        pos += 5 + len;
        match id {
            FIELD_KDF_PARAMETERS => return data,
            FIELD_END_OF_HEADER => panic!("в заголовке нет KdfParameters"),
            _ => {}
        }
    }
}

fn kdf_uuid(file: &[u8]) -> [u8; 16] {
    let dict = kdf_parameters(file);
    let mut pos = VARIANT_DICT_START;
    while dict[pos] != VARIANT_END {
        let key_len = read_u32(dict, pos + 1);
        let key = &dict[pos + 5..pos + 5 + key_len];
        pos += 5 + key_len;
        let val_len = read_u32(dict, pos);
        let value = &dict[pos + 4..pos + 4 + val_len];
        pos += 4 + val_len;
        if key == KDF_UUID_KEY {
            return value.try_into().expect("$UUID должен быть 16 байт");
        }
    }
    panic!("в KdfParameters нет $UUID");
}

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("okp_kdf_written_{}_{}.kdbx", name, std::process::id()));
    p.to_str().unwrap().to_string()
}

// Как клиент: только algorithm, без внутренних полей Argon2Kdf. Память и итерации
// уменьшены, чтобы тест был быстрым в debug; на выбор варианта они не влияют.
fn client_new_db(db_key: &str, algorithm: &str) -> NewDatabase {
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("KdfWrittenDb");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({
        "algorithm": algorithm,
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    serde_json::from_value(v).unwrap()
}

fn assert_written_kdf(algorithm: &str, expected_uuid: [u8; 16]) {
    common::init();
    let db_key = temp_path(algorithm);
    let _ = std::fs::remove_file(&db_key);

    db_service::create_kdbx(client_new_db(&db_key, algorithm)).unwrap();
    db_service::close_kdbx(&db_key).unwrap();

    let file = std::fs::read(&db_key).unwrap();
    let written = kdf_uuid(&file);

    // Файл должен открываться: ключ выведен тем же KDF, что записан в заголовок
    db_service::load_kdbx(&db_key, Some(PASSWORD), None).unwrap();
    db_service::close_kdbx(&db_key).unwrap();
    let _ = std::fs::remove_file(&db_key);

    assert_eq!(
        written, expected_uuid,
        "запрошен {}, а в заголовке записан другой KDF",
        algorithm
    );
}

#[test]
fn verify_argon2d_written_to_header() {
    assert_written_kdf("Argon2d", ARGON2_D_UUID);
}

#[test]
fn verify_argon2id_written_to_header() {
    assert_written_kdf("Argon2id", ARGON2_ID_UUID);
}
