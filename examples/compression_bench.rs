//! Замер gzip-компрессии: бэкенд `zlib` (C, крейт `libz-sys`) против `miniz_oxide` (чистый Rust).
//!
//! Нужен для Step 15 п.1: убрать фичу `zlib` у `flate2` — тогда уходит последняя C-зависимость и
//! ядро собирается без C-компилятора. Цена — скорость, поэтому меряем до и после переключения.
//!
//! Две части:
//!   A. Прямой замер `util::compress` / `util::decompress` на синтетическом XML, похожем на содержимое
//!      базы. Изолирует ровно то, что меняется. Заодно печатает размер сжатого блока: бэкенды жмут
//!      по-разному, а от этого зависит размер файла базы.
//!   B. Сквозной `save_kdbx` / `load_kdbx` базы с записями — показывает, какую долю компрессия
//!      занимает в реальной операции. Параметры Argon2 занижены намеренно: с дефолтными 64 MiB KDF
//!      съел бы всё время и разницу в компрессии не было бы видно.
//!
//! Использование (только release — debug-цифры для чистого Rust бессмысленны):
//!     cargo run --release --example compression_bench
//!
//! Бэкенд определяется `Cargo.toml`: `flate2 = { features = ["zlib"] }` или без фичи.

// Key store из интеграционных тестов. Логгер не включаем: debug-логи ядра искажали бы замеры.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use kdbx_rust_core::db_content;
use kdbx_rust_core::db_service::{self, NewDatabase};
use kdbx_rust_core::util;
use uuid::Uuid;

const PASSWORD: &str = "bench-pass-1234";
const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;
const MIB: usize = 1024 * 1024;

// Часть B: сколько записей в базе. 2000 даёт XML порядка нескольких MB — то есть база, какую можно
// реально встретить, а не пустышка из фикстур (те ~2 KB).
const ENTRY_COUNT: usize = 2000;

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn median(samples: &mut [Duration]) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

// ─────────────────────────────────────────────────────────────────────────────
// Часть A: прямой замер кодека
// ─────────────────────────────────────────────────────────────────────────────

// Полезная нагрузка, похожая на XML базы: повторяющаяся разметка плюс неповторяющиеся значения
// (uuid-подобные строки). Чистый повтор сжимался бы нереалистично хорошо.
fn xml_like_payload(target_len: usize) -> Vec<u8> {
    let mut out = String::with_capacity(target_len + 512);
    let mut n: u64 = 0;
    while out.len() < target_len {
        n = n
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push_str("<Entry><UUID>");
        out.push_str(&format!("{:032x}", n));
        out.push_str("</UUID><String><Key>UserName</Key><Value>user");
        out.push_str(&format!("{}", n % 100000));
        out.push_str("@example.com</Value></String><String><Key>Password</Key>");
        out.push_str("<Value ProtectInMemory=\"True\">");
        out.push_str(&format!("{:024x}", n >> 3));
        out.push_str("</Value></String><Times><LastModificationTime>");
        out.push_str("2026-09-19T10:00:00Z</LastModificationTime></Times></Entry>\n");
    }
    out.into_bytes()
}

fn bench_codec(size_mib: usize) {
    let data = xml_like_payload(size_mib * MIB);

    for _ in 0..WARMUP_RUNS {
        let c = util::compress(&data).unwrap();
        util::decompress(&c).unwrap();
    }

    let mut comp: Vec<Duration> = Vec::with_capacity(MEASURED_RUNS);
    let mut decomp: Vec<Duration> = Vec::with_capacity(MEASURED_RUNS);
    let mut compressed_len = 0usize;

    for _ in 0..MEASURED_RUNS {
        let start = Instant::now();
        let c = util::compress(&data).unwrap();
        comp.push(start.elapsed());
        compressed_len = c.len();

        let start = Instant::now();
        let d = util::decompress(&c).unwrap();
        decomp.push(start.elapsed());
        assert_eq!(d.len(), data.len(), "round-trip изменил размер");
    }

    println!(
        "{:>3} MiB  compress {:>8.1} ms | decompress {:>8.1} ms | сжато до {:>7.2} MiB ({:.1}%)",
        size_mib,
        millis(median(&mut comp)),
        millis(median(&mut decomp)),
        compressed_len as f64 / MIB as f64,
        100.0 * compressed_len as f64 / data.len() as f64,
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Часть B: сквозной save/load
// ─────────────────────────────────────────────────────────────────────────────

// NewDatabase собирается через serde: поля pub(crate). Параметры Argon2 занижены намеренно (см. шапку).
fn new_db(db_key: &str) -> NewDatabase {
    let mut value = serde_json::to_value(NewDatabase::default()).unwrap();
    value["database_name"] = serde_json::json!("CompressionBench");
    value["database_file_name"] = serde_json::json!(db_key);
    value["password"] = serde_json::json!(PASSWORD);
    value["cipher_id"] = serde_json::json!("Aes256");
    value["kdf"] = serde_json::json!({
        "algorithm": "Argon2id",
        "memory": 1024u64 * 1024,
        "iterations": 1u64,
        "parallelism": 1u32,
    });
    serde_json::from_value(value).unwrap()
}

fn add_entry(db_key: &str, parent_group_uuid: &Uuid, i: usize) {
    let login_type_uuid = db_content::standard_type_uuid_by_name("Login");
    let form =
        db_service::new_entry_form_data_by_id(db_key, login_type_uuid, Some(parent_group_uuid))
            .unwrap();

    let mut value = serde_json::to_value(&form).unwrap();
    value["title"] = serde_json::json!(format!("Entry {}", i));

    let section = value["section_fields"]["Login Details"]
        .as_array_mut()
        .unwrap();
    for field in section.iter_mut() {
        match field["key"].as_str() {
            Some("UserName") => {
                field["value"] = serde_json::json!(format!("user{}@example.com", i))
            }
            Some("Password") => {
                field["value"] = serde_json::json!(format!("p{:0>24x}", i * 2654435761))
            }
            Some("URL") => field["value"] = serde_json::json!(format!("https://site{}.example", i)),
            _ => {}
        }
    }

    let form = serde_json::from_value(value).unwrap();
    db_service::insert_entry_from_form_data(db_key, form).unwrap();
}

fn bench_end_to_end(dir: &std::path::Path) {
    let db_key = dir.join("bench.kdbx").to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&db_key);

    db_service::create_kdbx(new_db(&db_key)).unwrap();
    let root_uuid = db_service::groups_summary_data(&db_key).unwrap().root_uuid;

    for i in 0..ENTRY_COUNT {
        add_entry(&db_key, &root_uuid, i);
    }

    let mut save: Vec<Duration> = Vec::with_capacity(MEASURED_RUNS);
    let mut load: Vec<Duration> = Vec::with_capacity(MEASURED_RUNS);

    for run in 0..(WARMUP_RUNS + MEASURED_RUNS) {
        let start = Instant::now();
        db_service::save_kdbx_with_backup(&db_key, None, true).unwrap();
        let saved = start.elapsed();

        db_service::close_kdbx(&db_key).unwrap();

        let start = Instant::now();
        db_service::load_kdbx(&db_key, Some(PASSWORD), None).unwrap();
        let loaded = start.elapsed();

        if run >= WARMUP_RUNS {
            save.push(saved);
            load.push(loaded);
        }
    }

    let file_size = std::fs::metadata(&db_key).unwrap().len();
    println!(
        "{} записей: save {:>8.1} ms | load {:>8.1} ms | файл {:>7.2} MiB",
        ENTRY_COUNT,
        millis(median(&mut save)),
        millis(median(&mut load)),
        file_size as f64 / MIB as f64,
    );

    db_service::close_kdbx(&db_key).unwrap();
    let _ = std::fs::remove_file(&db_key);
}

fn main() {
    // Debug-цифры по умолчанию не нужны: они не про продакшен. Но именно они показывают, во что
    // превращается чистый Rust без оптимизации, — а в этом профиле идут тесты и debug-сборки Android.
    // Поэтому debug разрешён явным OKP_BENCH_DEBUG=1.
    if cfg!(debug_assertions) && std::env::var("OKP_BENCH_DEBUG").is_err() {
        eprintln!("Запускайте с --release (или OKP_BENCH_DEBUG=1, чтобы померить debug осознанно)");
        std::process::exit(1);
    }

    let dir = std::env::temp_dir().join("kdbx_compression_bench");
    std::fs::create_dir_all(&dir).unwrap();
    common::init_key_main_store();

    println!(
        "runs: {} warmup + {} measured | flate2 zlib feature: см. Cargo.toml",
        WARMUP_RUNS, MEASURED_RUNS
    );
    println!();

    println!("A. кодек напрямую (util::compress / util::decompress)");
    for size in [1usize, 4, 16] {
        bench_codec(size);
    }
    println!();

    println!("B. сквозной save_kdbx / load_kdbx");
    bench_end_to_end(&dir);
}
