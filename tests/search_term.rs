//! Поиск записей (Step 41): по названию и полю «Пользователь», как их показывает карточка (плейсхолдеры
//! подставлены), без учёта регистра, строка — текст, а не regex; защищённые поля не смотрим; корзина и
//! группы внутри неё не ищутся.

mod common;

use kdbx_rust_core::db_service::{self, NewDatabase};
use serde_json::{json, Value};
use uuid::Uuid;

const PASSWORD: &str = "search-term-1234";

struct Db(String);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = db_service::close_kdbx(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}

// KDF уменьшен, чтобы тест был быстрым в debug
fn create_db(name: &str) -> Db {
    common::init();
    let mut p = std::env::temp_dir();
    p.push(format!("okp_search_{}_{}.kdbx", name, std::process::id()));
    let db_key = p.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&db_key);

    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = json!("Search");
    v["database_file_name"] = json!(db_key);
    v["password"] = json!(PASSWORD);
    v["kdf"] = json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    db_service::create_kdbx(serde_json::from_value(v).unwrap()).unwrap();
    Db(db_key)
}

fn root(db: &Db) -> Uuid {
    db_service::groups_summary_data(&db.0).unwrap().root_uuid
}

fn add_group(db: &Db, parent: Uuid, name: &str) -> Uuid {
    let group = db_service::new_blank_group_with_parent(parent, false).unwrap();
    let mut v = serde_json::to_value(&group).unwrap();
    v["name"] = json!(name);
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    db_service::insert_group(&db.0, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

/// Запись с полями `(ключ, значение)`; ключи из `protected` — защищённые.
fn add_entry(db: &Db, group: Uuid, fields: &[(&str, &str)], protected: &[&str]) -> Uuid {
    let form = db_service::new_entry_form_data(Some(&group));
    let mut v = serde_json::to_value(&form).unwrap();
    for (key, value) in fields {
        common::form::set_field(&mut v, key, value);
    }
    for key in protected {
        common::form::protect(&mut v, key);
    }
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    db_service::insert_entry_from_form_data(&db.0, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

fn search(db: &Db, term: &str) -> Value {
    serde_json::to_value(db_service::search_term(&db.0, term).unwrap()).unwrap()
}

fn found_titles(db: &Db, term: &str) -> Vec<String> {
    let mut titles: Vec<String> = search(db, term)["entry_items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["title"].as_str().unwrap_or_default().to_string())
        .collect();
    titles.sort();
    titles
}

#[test]
fn finds_by_title_and_user_name_whatever_the_case() {
    let db = create_db("title_user");
    let root = root(&db);
    add_entry(
        &db,
        root,
        &[("Title", "Bank of the North"), ("UserName", "alice")],
        &[],
    );
    add_entry(
        &db,
        root,
        &[("Title", "Mail"), ("UserName", "ALICE@mail")],
        &[],
    );
    add_entry(&db, root, &[("Title", "Почта"), ("UserName", "bob")], &[]);

    assert_eq!(found_titles(&db, "bank"), vec!["Bank of the North"]);
    assert_eq!(
        found_titles(&db, "Alice"),
        vec!["Bank of the North", "Mail"]
    );
    assert_eq!(found_titles(&db, "ПОЧ"), vec!["Почта"]);
}

#[test]
fn the_password_and_other_fields_are_not_looked_into() {
    let db = create_db("other_fields");
    let root = root(&db);
    add_entry(
        &db,
        root,
        &[
            ("Title", "Shop"),
            ("Password", "hunter2"),
            ("URL", "https://shop.example"),
            ("Notes", "gift card"),
        ],
        &["Password"],
    );

    assert!(found_titles(&db, "hunter2").is_empty());
    assert!(found_titles(&db, "example").is_empty());
    assert!(found_titles(&db, "gift").is_empty());
}

#[test]
fn a_protected_title_or_user_name_is_not_looked_into() {
    let db = create_db("protected");
    let root = root(&db);
    add_entry(
        &db,
        root,
        &[("Title", "Secret title"), ("UserName", "carol")],
        &["Title", "UserName"],
    );

    assert!(found_titles(&db, "secret").is_empty());
    assert!(found_titles(&db, "carol").is_empty());
}

#[test]
fn the_term_is_text_and_not_a_pattern() {
    let db = create_db("pattern");
    let root = root(&db);
    add_entry(&db, root, &[("Title", "c++ (work)")], &[]);
    add_entry(&db, root, &[("Title", "Mail")], &[]);

    assert_eq!(found_titles(&db, "c++"), vec!["c++ (work)"]);
    assert_eq!(found_titles(&db, "(work"), vec!["c++ (work)"]);
    // Раньше — RegexError и «найти всё» на точку
    assert!(found_titles(&db, "user\\").is_empty());
    assert!(found_titles(&db, ".").is_empty());
}

#[test]
fn a_blank_term_finds_nothing_and_comes_back() {
    let db = create_db("blank");
    add_entry(&db, root(&db), &[("Title", "Mail")], &[]);

    let result = search(&db, "   ");
    assert_eq!(result["term"], "   ");
    assert!(result["entry_items"].as_array().unwrap().is_empty());
}

#[test]
fn the_recycle_bin_and_the_groups_inside_it_are_not_looked_at() {
    let db = create_db("recycle_bin");
    let root = root(&db);
    let kept = add_group(&db, root, "Kept");
    let gone = add_group(&db, root, "Gone");
    let inner = add_group(&db, gone, "Inner");

    add_entry(&db, kept, &[("Title", "Bank kept")], &[]);
    let binned = add_entry(&db, root, &[("Title", "Bank binned")], &[]);
    add_entry(&db, inner, &[("Title", "Bank in a binned group")], &[]);

    db_service::delete_entry(&db.0, binned).unwrap();
    db_service::delete_group(&db.0, gone).unwrap();

    assert_eq!(found_titles(&db, "bank"), vec!["Bank kept"]);
}

#[test]
fn values_are_matched_as_the_card_shows_them_place_holders_resolved() {
    let db = create_db("place_holders");
    add_entry(
        &db,
        root(&db),
        &[("Title", "{USERNAME} mail"), ("UserName", "dave")],
        &[],
    );

    assert_eq!(found_titles(&db, "dave mail"), vec!["dave mail"]);
}

#[test]
fn a_found_entry_carries_its_group_and_creation_time() {
    let db = create_db("summary");
    let group = add_group(&db, root(&db), "Work");
    let entry = add_entry(&db, group, &[("Title", "Jira")], &[]);

    let result = search(&db, "jira");
    let item = &result["entry_items"][0];
    assert_eq!(item["uuid"], entry.to_string());
    assert_eq!(item["parent_group_uuid"], group.to_string());
    assert!(item["created_time"].as_i64().is_some(), "{}", item);
}
