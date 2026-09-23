//! Открывает базу нашим ядром и сохраняет её в новый файл — без каких-либо правок.
//!
//! Нужен `tools/kdbx-oracle/compare_roundtrip.py`: тот сравнивает XML исходной и
//! пересохранённой базы и показывает, что ядро потеряло или изменило. Отдельная
//! CI-job, не часть `cargo test`.
//!
//! Использование:
//!     cargo run --quiet --example resave_db -- <исходная.kdbx> <новая.kdbx> <пароль>

// Key store из интеграционных тестов, как в write_roundtrip_dbs.rs.
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

use onekeepass_core::db_service;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, source, target, password] = args.as_slice() else {
        eprintln!("usage: resave_db <source.kdbx> <target.kdbx> <password>");
        std::process::exit(2);
    };

    common::init_key_main_store();

    // db_key в ядре — путь к файлу; исходник только читается.
    db_service::load_kdbx(source, Some(password), None)
        .unwrap_or_else(|e| panic!("cannot open {}: {:?}", source, e));
    db_service::save_to_db_file(source, target)
        .unwrap_or_else(|e| panic!("cannot save {}: {:?}", target, e));
    let _ = db_service::close_kdbx(source);
}
