//! Какой вид ошибки (`kind` в FFI — имя варианта) приходит на какую поломку файла (Step 30).
//!
//! Имя варианта — контракт: мост отдаёт его приложению, и UI ветвится по нему, не читая текст. Step 28
//! строит на этом маппинг в узкий тип ошибок экрана, поэтому здесь закреплено, что ядро отдаёт **на самом
//! деле**, а не что можно было бы предположить по коду:
//!
//! - не те учётные данные — `InvalidCredentials`;
//! - испорчен байт в заголовке — `HeaderCorrupted`: хэш заголовка проверяется до ключа, так что пароль тут
//!   ни при чём, даже неверный;
//! - испорчен байт в содержимом — `ContentCorrupted`: блоки проверяются HMAC уже с верным ключом;
//! - файл обрезан (недокачанная синхронизация) — тоже «повреждён», на любой длине: `HeaderCorrupted` или
//!   `ContentCorrupted` в зависимости от того, где оборвался.
//!
//! Чтение — через `read_kdbx` из байтов, как это делает приложение.

mod common;

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service::{self, Error};

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "aes256_argon2d.kdbx";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn fixture() -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(FIXTURE);
    std::fs::read(path).unwrap()
}

fn read(bytes: Vec<u8>, password: &str) -> db_service::Result<db_service::KdbxLoaded> {
    common::init();
    let db_key = format!(
        "content://test/{}/{}/kinds.kdbx",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let loaded =
        db_service::read_kdbx(&mut Cursor::new(bytes), &db_key, Some(password), None, None);
    if loaded.is_ok() {
        db_service::close_kdbx(&db_key).unwrap();
    }
    loaded
}

/// Внешний заголовок KDBX4: 12 байт сигнатур и версии, затем поля TLV — тип 1 байт, длина 4 байта LE,
/// данные. Поле типа 0 — конец заголовка. Возвращает смещение данных поля `field_type` и смещение
/// первого байта после заголовка.
fn header_layout(bytes: &[u8], field_type: u8) -> (usize, usize) {
    let mut pos = 12;
    let mut field_data = None;
    loop {
        let kind = bytes[pos];
        let len = u32::from_le_bytes(bytes[pos + 1..pos + 5].try_into().unwrap()) as usize;
        let data = pos + 5;
        if kind == field_type {
            field_data = Some(data);
        }
        pos = data + len;
        if kind == 0 {
            return (field_data.expect("нет такого поля"), pos);
        }
    }
}

const MASTER_SEED: u8 = 4;

#[test]
fn the_fixture_opens_untouched() {
    read(fixture(), PASSWORD).unwrap();
}

#[test]
fn a_wrong_password_is_invalid_credentials() {
    let loaded = read(fixture(), "wrong-password");
    assert!(
        matches!(loaded, Err(Error::InvalidCredentials)),
        "{:?}",
        loaded.err()
    );
}

#[test]
fn a_damaged_header_is_header_corrupted_whatever_the_password() {
    let mut bytes = fixture();
    let (seed, _) = header_layout(&bytes, MASTER_SEED);
    bytes[seed] ^= 0xFF;

    for password in [PASSWORD, "wrong-password"] {
        let loaded = read(bytes.clone(), password);
        assert!(
            matches!(loaded, Err(Error::HeaderCorrupted)),
            "с паролем {:?}: {:?}",
            password,
            loaded.err()
        );
    }
}

#[test]
fn damaged_content_is_content_corrupted() {
    let mut bytes = fixture();
    let (_, header_end) = header_layout(&bytes, MASTER_SEED);
    // За заголовком: sha256 заголовка (32) и его HMAC (32), затем первый блок — HMAC блока (32), длина
    // (4) и данные. Портим байт внутри данных блока
    let block_data = header_end + 32 + 32 + 32 + 4;
    bytes[block_data + 10] ^= 0xFF;

    let loaded = read(bytes, PASSWORD);
    assert!(
        matches!(loaded, Err(Error::ContentCorrupted)),
        "{:?}",
        loaded.err()
    );
}

/// Недокачанный файл — «повреждён» на **любой** длине, а не то, обо что чтение споткнулось первым
/// (`Io`, `UnexpectedError` из разбора полей, `ContentCorrupted` — до Step 30 приходило всё это):
/// обрыв в заголовке — `HeaderCorrupted`, в содержимом — `ContentCorrupted`.
///
/// Каждый байт там, где меняется структура: весь заголовок, начало первого блока (HMAC и длина) и хвост
/// файла (последний, пустой блок). Середина содержимого — с шагом 16: там один и тот же случай, а каждая
/// длина за заголовком платит за Argon2, и полный перебор стоил бы ~20 с на прогон.
#[test]
fn a_truncated_file_is_corrupted_at_any_length() {
    let bytes = fixture();
    let (_, header_end) = header_layout(&bytes, MASTER_SEED);
    // Заголовок кончается вместе со своими хэшем и HMAC
    let content_start = header_end + 32 + 32;
    let first_block_data = content_start + 32 + 4;
    let tail = bytes.len() - 64;

    let cuts = (0..first_block_data + 8)
        .chain((first_block_data + 8..tail).step_by(16))
        .chain(tail..bytes.len());

    for cut in cuts {
        let loaded = read(bytes[..cut].to_vec(), PASSWORD);
        let ok = if cut < content_start {
            matches!(loaded, Err(Error::HeaderCorrupted))
        } else {
            matches!(loaded, Err(Error::ContentCorrupted))
        };
        assert!(
            ok,
            "обрезан до {} байт из {} (содержимое с {}): {:?}",
            cut,
            bytes.len(),
            content_start,
            loaded.err()
        );
    }
}

#[test]
fn not_a_keepass_file_stays_what_it_is() {
    // Целый файл, но не kdbx — это ответ о файле, а не повреждение
    let loaded = read(
        b"just some text that is long enough for a header".to_vec(),
        PASSWORD,
    );
    assert!(
        matches!(loaded, Err(Error::InvalidKeePassFile)),
        "{:?}",
        loaded.err()
    );
}
