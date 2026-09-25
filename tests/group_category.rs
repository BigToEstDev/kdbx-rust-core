//! Флаг «категория» у группы должен переживать сохранение и повторное открытие файла.
//!
//! В файле флаг хранится маркером в custom data группы (`OKP_K2 = "No"` — не категория;
//! нет маркера — категория, так устроены группы из других клиентов). Снятая отметка раньше
//! возвращалась при следующем открытии: проверка маркера была перевёрнута.

mod common;

use kdbx_rust_core::db_service::{self, NewDatabase};
use uuid::Uuid;

const PASSWORD: &str = "group-category-1234";

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "okp_group_category_{}_{}.kdbx",
        name,
        std::process::id()
    ));
    p.to_str().unwrap().to_string()
}

// KDF уменьшен, чтобы тест был быстрым в debug
fn create_db(db_key: &str) {
    common::init();
    let _ = std::fs::remove_file(db_key);
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = serde_json::json!("GroupCategory");
    v["database_file_name"] = serde_json::json!(db_key);
    v["password"] = serde_json::json!(PASSWORD);
    v["kdf"] = serde_json::json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();
    db_service::create_kdbx(new_db).unwrap();
}

fn add_category_group(db_key: &str) -> Uuid {
    let root_uuid = db_service::groups_summary_data(db_key).unwrap().root_uuid;
    let group = db_service::new_blank_group_with_parent(root_uuid, true).unwrap();
    let v = serde_json::to_value(&group).unwrap();
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    db_service::insert_group(db_key, group).unwrap();
    uuid
}

fn is_category(db_key: &str, group_uuid: &Uuid) -> bool {
    let v = serde_json::to_value(db_service::get_group_by_id(db_key, group_uuid).unwrap()).unwrap();
    v["marked_category"].as_bool().unwrap()
}

fn set_category(db_key: &str, group_uuid: &Uuid, category: bool) {
    let mut v =
        serde_json::to_value(db_service::get_group_by_id(db_key, group_uuid).unwrap()).unwrap();
    v["marked_category"] = serde_json::json!(category);
    db_service::update_group(db_key, serde_json::from_value(v).unwrap()).unwrap();
}

fn save_and_reopen(db_key: &str) {
    db_service::save_kdbx_with_backup(db_key, None, false).unwrap();
    db_service::close_kdbx(db_key).unwrap();
    db_service::load_kdbx(db_key, Some(PASSWORD), None).unwrap();
}

#[test]
fn unmarked_category_survives_save_and_reopen() {
    let db_key = temp_path("unmark");
    create_db(&db_key);
    let group = add_category_group(&db_key);

    set_category(&db_key, &group, false);
    save_and_reopen(&db_key);
    let after_first = is_category(&db_key, &group);
    // Второй цикл: маркер уже в файле, и он не должен «переключаться» обратно
    save_and_reopen(&db_key);
    let after_second = is_category(&db_key, &group);

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
    assert!(
        !after_first,
        "после первого сохранения группа снова категория"
    );
    assert!(
        !after_second,
        "после второго сохранения группа снова категория"
    );
}

#[test]
fn marked_category_survives_save_and_reopen() {
    let db_key = temp_path("mark");
    create_db(&db_key);
    let group = add_category_group(&db_key);

    set_category(&db_key, &group, false);
    save_and_reopen(&db_key);
    set_category(&db_key, &group, true);
    save_and_reopen(&db_key);
    let category = is_category(&db_key, &group);

    let _ = db_service::close_kdbx(&db_key);
    let _ = std::fs::remove_file(&db_key);
    assert!(category);
}
