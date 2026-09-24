//! Открывает базу нашим ядром и сохраняет её в новый файл — без каких-либо правок.
//!
//! Нужен `tools/kdbx-oracle/compare_roundtrip.py`: тот сравнивает XML исходной и
//! пересохранённой базы и показывает, что ядро потеряло или изменило. Отдельная
//! CI-job, не часть `cargo test`.
//!
//! Использование:
//!     cargo run --quiet --example resave_db -- <исходная.kdbx> <новая.kdbx> <пароль> [ключевой файл]

// Key store из интеграционных тестов, как в write_roundtrip_dbs.rs.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use onekeepass_core::db_service;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (source, target, password, key_file) = match args.as_slice() {
        [_, source, target, password] => (source, target, password, None),
        [_, source, target, password, key_file] => (source, target, password, Some(key_file)),
        _ => {
            eprintln!("usage: resave_db <source.kdbx> <target.kdbx> <password> [key file]");
            std::process::exit(2);
        }
    };

    common::init_key_main_store();

    // db_key в ядре — путь к файлу; исходник только читается.
    db_service::load_kdbx(source, Some(password), key_file.map(|k| k.as_str()))
        .unwrap_or_else(|e| panic!("cannot open {}: {:?}", source, e));
    db_service::save_to_db_file(source, target)
        .unwrap_or_else(|e| panic!("cannot save {}: {:?}", target, e));
    let _ = db_service::close_kdbx(source);
}
