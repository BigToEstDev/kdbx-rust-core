//! Замер времени открытия базы при разных параметрах Argon2.
//!
//! Меряется `load_kdbx` пустой базы: на ней время почти целиком уходит на KDF, а XML и
//! шифр контента дают доли миллисекунды. Идёт только через публичный API, поэтому один и
//! тот же пример сравнивает реализации Argon2 до и после замены (Step 10).
//!
//! Использование (только release — debug-цифры для Argon2 бессмысленны):
//!     cargo run --release --example argon2_bench

// Key store из интеграционных тестов. Логгер не включаем (только init_key_main_store):
// debug-логи ядра засоряли бы вывод и искажали замеры.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use onekeepass_core::db_service::{self, NewDatabase};

const PASSWORD: &str = "bench-pass-1234";
const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;
const MIB: u64 = 1024 * 1024;

// Значения поля `variant` в Argon2Kdf (crypto/kdf.rs). Передавать явно обязательно:
// без него serde(default) подставит Argon2d даже для algorithm = "Argon2id".
const VARIANT_ARGON2_D: u32 = 0;
const VARIANT_ARGON2_ID: u32 = 2;

struct KdfCase {
    name: &'static str,
    algorithm: &'static str,
    variant: u32,
    memory: u64,
    iterations: u64,
    parallelism: u32,
}

const CASES: &[KdfCase] = &[
    KdfCase {
        name: "argon2d_64mib_i10_p2 (default)",
        algorithm: "Argon2d",
        variant: VARIANT_ARGON2_D,
        memory: 64 * MIB,
        iterations: 10,
        parallelism: 2,
    },
    KdfCase {
        name: "argon2id_64mib_i10_p2",
        algorithm: "Argon2id",
        variant: VARIANT_ARGON2_ID,
        memory: 64 * MIB,
        iterations: 10,
        parallelism: 2,
    },
    KdfCase {
        name: "argon2d_64mib_i10_p1",
        algorithm: "Argon2d",
        variant: VARIANT_ARGON2_D,
        memory: 64 * MIB,
        iterations: 10,
        parallelism: 1,
    },
    KdfCase {
        name: "argon2d_64mib_i10_p4",
        algorithm: "Argon2d",
        variant: VARIANT_ARGON2_D,
        memory: 64 * MIB,
        iterations: 10,
        parallelism: 4,
    },
];

// NewDatabase собирается через serde: поля pub(crate). KdfAlgorithm — internally tagged.
fn new_db(db_key: &str, case: &KdfCase) -> NewDatabase {
    let mut value = serde_json::to_value(NewDatabase::default()).unwrap();
    value["database_name"] = serde_json::json!("Argon2Bench");
    value["database_file_name"] = serde_json::json!(db_key);
    value["password"] = serde_json::json!(PASSWORD);
    value["cipher_id"] = serde_json::json!("Aes256");
    value["kdf"] = serde_json::json!({
        "algorithm": case.algorithm,
        "variant": case.variant,
        "memory": case.memory,
        "iterations": case.iterations,
        "parallelism": case.parallelism,
    });
    serde_json::from_value(value).unwrap()
}

fn time_load(db_key: &str) -> Duration {
    let start = Instant::now();
    db_service::load_kdbx(db_key, Some(PASSWORD), None).unwrap();
    let elapsed = start.elapsed();
    db_service::close_kdbx(db_key).unwrap();
    elapsed
}

fn millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn run_case(dir: &std::path::Path, case: &KdfCase) {
    let db_key = dir
        .join(format!("{}.kdbx", case.algorithm.to_lowercase()))
        .to_string_lossy()
        .into_owned();
    let _ = std::fs::remove_file(&db_key);

    db_service::create_kdbx(new_db(&db_key, case)).unwrap();
    db_service::close_kdbx(&db_key).unwrap();

    for _ in 0..WARMUP_RUNS {
        time_load(&db_key);
    }
    let mut samples: Vec<Duration> = (0..MEASURED_RUNS).map(|_| time_load(&db_key)).collect();
    samples.sort();

    println!(
        "{:<32} min {:>7.1} ms | median {:>7.1} ms | max {:>7.1} ms",
        case.name,
        millis(samples[0]),
        millis(samples[samples.len() / 2]),
        millis(samples[samples.len() - 1]),
    );

    let _ = std::fs::remove_file(&db_key);
}

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("Запускайте с --release: debug-сборка искажает цифры Argon2");
        std::process::exit(1);
    }

    let dir = std::env::temp_dir().join("onekeepass_argon2_bench");
    std::fs::create_dir_all(&dir).unwrap();
    common::init_key_main_store();

    println!(
        "runs: {} warmup + {} measured, cores: {}",
        WARMUP_RUNS,
        MEASURED_RUNS,
        std::thread::available_parallelism().map_or(0, |n| n.get()),
    );
    for case in CASES {
        run_case(&dir, case);
    }
}
