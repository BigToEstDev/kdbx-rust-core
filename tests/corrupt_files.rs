//! Испорченный чужой файл даёт ошибку, а не панику (Step 19, п.1).
//!
//! Приложение открывает файлы, которые ему дал пользователь: обрезанные синхронизацией,
//! недокачанные, повреждённые на диске. Паника в ядре — это падение всего приложения и,
//! после FFI, падение Android-процесса; пользователь при этом не узнает, что именно не так
//! с его файлом. Любая поломка входных данных должна возвращаться как `Err`.
//!
//! Размеры обрезки не случайны: на 16 и 80 байтах ядро падало в `read_header_field`, на 280 —
//! в `verify_stored_hash` (`src/db/reader_writer.rs`, снято 2026-09-24 до правки).

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use kdbx_rust_core::db_service;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "all_fields_41.kdbx";

static SEQ: AtomicU64 = AtomicU64::new(0);

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

fn temp_path(suffix: &str) -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_corrupt_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    target.to_str().unwrap().to_string()
}

/// Первые `size` байт фикстуры в отдельном файле.
fn truncated_copy(size: usize) -> String {
    let data = std::fs::read(resource(FIXTURE)).unwrap();
    let path = temp_path(&format!("head_{}.kdbx", size));
    std::fs::write(&path, &data[..size.min(data.len())]).unwrap();
    path
}

fn try_open(db_key: &str) -> bool {
    let opened = db_service::load_kdbx(db_key, Some(PASSWORD), None).is_ok();
    if opened {
        let _ = db_service::close_kdbx(db_key);
    }
    let _ = std::fs::remove_file(db_key);
    opened
}

/// Файл, обрезанный на любой длине, не должен ронять ядро. Шаг в 4 байта проходит по всем
/// границам полей внешнего заголовка (TLV: тип 1 байт, длина 4 байта).
#[test]
fn a_truncated_file_gives_an_error_at_any_length() {
    common::init();

    let full = std::fs::read(resource(FIXTURE)).unwrap().len();
    for size in (0..600).step_by(4) {
        let path = truncated_copy(size);
        assert!(
            !try_open(&path),
            "файл из первых {} байт (из {}) открылся как целая база",
            size,
            full
        );
    }
}

/// Точки, на которых ядро падало до Step 19 — отдельным тестом, чтобы регрессия была видна
/// по имени, а не тонула в переборе длин.
#[test]
fn known_panic_points_give_an_error() {
    common::init();

    for size in [16, 80, 280] {
        let path = truncated_copy(size);
        assert!(
            !try_open(&path),
            "файл из первых {} байт открылся как целая база",
            size
        );
    }
}

/// Целый по длине файл, но с испорченной серединой: заголовок читается, расшифровка — нет.
#[test]
fn a_damaged_body_gives_an_error() {
    common::init();

    let mut data = std::fs::read(resource(FIXTURE)).unwrap();
    let middle = data.len() / 2;
    for byte in data[middle..middle + 64].iter_mut() {
        *byte ^= 0xFF;
    }
    let path = temp_path("damaged.kdbx");
    std::fs::write(&path, &data).unwrap();

    assert!(
        !try_open(&path),
        "база с испорченной серединой открылась как целая"
    );
}

/// Пустой файл — вырожденный случай того же пути чтения.
#[test]
fn an_empty_file_gives_an_error() {
    common::init();

    let path = temp_path("empty.kdbx");
    std::fs::write(&path, b"").unwrap();

    assert!(!try_open(&path), "пустой файл открылся как база");
}
