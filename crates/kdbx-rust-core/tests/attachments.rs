//! Вложения записи байтами (pass-docs, Step 102): в файл и в памяти — только то, на что ссылается запись или её
//! версия; через файл байты и имена доходят как были.

mod common;

use kdbx_rust_core::db_service::{self, NewDatabase};
use serde_json::{json, Value};
use uuid::Uuid;

const PASSWORD: &str = "attachments-1234";

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
    p.push(format!(
        "okp_attachments_{}_{}.kdbx",
        name,
        std::process::id()
    ));
    let db_key = p.to_str().unwrap().to_string();
    let _ = std::fs::remove_file(&db_key);
    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = json!("Attachments");
    v["database_file_name"] = json!(db_key);
    v["password"] = json!(PASSWORD);
    v["kdf"] = json!({
        "algorithm": "Argon2id",
        "memory": 1024 * 1024,
        "iterations": 1,
        "parallelism": 1,
    });
    let new_db: NewDatabase = serde_json::from_value(v).unwrap();
    db_service::create_kdbx(new_db).unwrap();
    Db(db_key)
}

fn save_and_reopen(db: &Db) {
    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();
    db_service::close_kdbx(&db.0).unwrap();
    db_service::load_kdbx(&db.0, Some(PASSWORD), None).unwrap();
}

// Uploads the bytes: the info the form of an entry links them with
fn upload(db: &Db, name: &str, data: &[u8]) -> Value {
    let info = db_service::upload_entry_attachment(&db.0, name, data.to_vec()).unwrap();
    json!({
        "key": info.name,
        "value": "",
        "index_ref": 0,
        "data_hash": info.data_hash.to_string(),
        "data_size": info.data_size,
    })
}

fn new_entry(db: &Db, attachments: Vec<Value>) -> Uuid {
    let root_uuid = db_service::groups_summary_data(&db.0).unwrap().root_uuid;
    let form = db_service::new_entry_form_data(Some(&root_uuid));
    let mut v = serde_json::to_value(&form).unwrap();
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    common::form::set_field(&mut v, "Title", "With attachments");
    v["binary_key_values"] = Value::Array(attachments);
    db_service::insert_entry_from_form_data(&db.0, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

fn set_attachments(db: &Db, entry: &Uuid, attachments: Vec<Value>) {
    let form = db_service::get_entry_form_data_by_id(&db.0, entry).unwrap();
    let mut v = serde_json::to_value(&form).unwrap();
    v["binary_key_values"] = Value::Array(attachments);
    db_service::update_entry_from_form_data(&db.0, serde_json::from_value(v).unwrap()).unwrap();
}

// The attachments of the entry as now: name and bytes, in its order
fn attachments_of(db: &Db, entry: &Uuid) -> Vec<(String, Vec<u8>)> {
    let form = db_service::get_entry_form_data_by_id(&db.0, entry).unwrap();
    let v = serde_json::to_value(&form).unwrap();
    v["binary_key_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            let hash: u64 = b["data_hash"].as_str().unwrap().parse().unwrap();
            (b["key"].as_str().unwrap().to_string(), bytes(db, hash))
        })
        .collect()
}

fn bytes(db: &Db, hash: u64) -> Vec<u8> {
    let mut out = vec![];
    db_service::save_attachment_to_writer(&db.0, &hash, &mut out).unwrap();
    out
}

fn hash_of(attachment: &Value) -> u64 {
    attachment["data_hash"].as_str().unwrap().parse().unwrap()
}

#[test]
fn the_attachments_of_an_entry_survive_the_file() {
    let db = create_db("survive");
    let a = upload(&db, "a.txt", b"first");
    let b = upload(&db, "b.bin", &[0, 1, 2, 255]);
    let entry = new_entry(&db, vec![a, b]);

    save_and_reopen(&db);

    assert_eq!(
        attachments_of(&db, &entry),
        vec![
            ("a.txt".to_string(), b"first".to_vec()),
            ("b.bin".to_string(), vec![0, 1, 2, 255]),
        ]
    );
}

#[test]
fn bytes_linked_with_no_entry_are_gone_after_the_write() {
    let db = create_db("unlinked");
    let linked = upload(&db, "kept.txt", b"kept");
    let unlinked = upload(&db, "lost.txt", b"never linked");
    new_entry(&db, vec![linked.clone()]);

    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();

    assert_eq!(bytes(&db, hash_of(&linked)), b"kept");
    let mut out = vec![];
    assert!(db_service::save_attachment_to_writer(&db.0, &hash_of(&unlinked), &mut out).is_err());
}

#[test]
fn an_attachment_removed_stays_while_a_version_links_it() {
    let db = create_db("version");
    let removed = upload(&db, "old.txt", b"in the version");
    let entry = new_entry(&db, vec![removed.clone()]);
    // The update keeps the entry before it as a version - with the attachment
    set_attachments(&db, &entry, vec![]);

    save_and_reopen(&db);

    assert!(attachments_of(&db, &entry).is_empty());
    assert_eq!(bytes(&db, hash_of(&removed)), b"in the version");
}
