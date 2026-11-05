//! Вложения записи байтами (pass-docs, Step 102): в файл и в памяти — только то, на что ссылается запись или её
//! версия; через файл байты и имена доходят как были.

mod common;

use kdbx_rust_core::db_service::{self, EntryCategory, NewAttachment, NewDatabase};
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

// Step 102 п. 3a: до правки вложение после блокировки не читалось - ядро связывало записи по номерам Ref времени
// чтения файла
#[test]
fn a_new_attachment_survives_a_lock() {
    let db = create_db("lock_new");
    let a = upload(&db, "a.txt", b"new one");
    let entry = new_entry(&db, vec![a]);

    db_service::lock_kdbx(&db.0).unwrap();
    db_service::unlock_kdbx(&db.0, Some(PASSWORD), None).unwrap();

    assert_eq!(
        attachments_of(&db, &entry),
        vec![("a.txt".to_string(), b"new one".to_vec())]
    );
}

#[test]
fn the_attachments_survive_a_lock_after_the_binaries_change_order() {
    let db = create_db("lock_saved");
    let a = upload(&db, "a.txt", b"aaa");
    let b = upload(&db, "b.txt", b"bbb");
    let first = new_entry(&db, vec![a]);
    let second = new_entry(&db, vec![b]);
    save_and_reopen(&db);
    // The first attachment gone for good - entry and versions: the binary of the second is another one now
    set_attachments(&db, &first, vec![]);
    db_service::delete_history_entries(&db.0, &first).unwrap();
    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();

    db_service::lock_kdbx(&db.0).unwrap();
    db_service::unlock_kdbx(&db.0, Some(PASSWORD), None).unwrap();

    assert_eq!(
        attachments_of(&db, &second),
        vec![("b.txt".to_string(), b"bbb".to_vec())]
    );
    // And the file written after the unlock reads them as well
    save_and_reopen(&db);
    assert_eq!(
        attachments_of(&db, &second),
        vec![("b.txt".to_string(), b"bbb".to_vec())]
    );
}

// Фикстура oracle (pykeepass): одинаковые байты двумя блоками inner header и третье вложение за ними. До Step 102
// индекс Ref считался по числу разных вложений - вложение третьей записи съезжало на чужой блок
const FIXTURE_PASSWORD: &str = "test-pass-1234";
const DUPLICATE_BINARIES: [(&str, &str, &[u8]); 3] = [
    ("First", "same.txt", b"the same bytes"),
    ("Second", "same-again.txt", b"the same bytes"),
    (
        "Third",
        "other.bin",
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    ),
];

fn open_fixture(name: &str) -> Db {
    common::init();
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/resources")
        .join(name);
    let mut p = std::env::temp_dir();
    p.push(format!("okp_attachments_{}_{}", std::process::id(), name));
    std::fs::copy(source, &p).unwrap();
    let db = Db(p.to_str().unwrap().to_string());
    db_service::load_kdbx(&db.0, Some(FIXTURE_PASSWORD), None).unwrap();
    db
}

fn entry_by_title(db: &Db, title: &str) -> Uuid {
    db_service::entry_summary_data(&db.0, EntryCategory::AllEntries)
        .unwrap()
        .iter()
        .find(|e| e.title.as_deref() == Some(title))
        .map(|e| Uuid::parse_str(&e.uuid).unwrap())
        .unwrap()
}

fn assert_duplicate_binaries(db: &Db) {
    for (title, name, data) in DUPLICATE_BINARIES {
        let entry = entry_by_title(db, title);
        assert_eq!(
            attachments_of(db, &entry),
            vec![(name.to_string(), data.to_vec())],
            "вложение записи {}",
            title
        );
    }
}

#[test]
fn the_same_bytes_in_two_binaries_keep_the_attachments_of_the_next_entries() {
    let db = open_fixture("duplicate_binaries_41.kdbx");
    assert_duplicate_binaries(&db);

    // Written by the core - the same bytes once - and read again
    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();
    db_service::close_kdbx(&db.0).unwrap();
    db_service::load_kdbx(&db.0, Some(FIXTURE_PASSWORD), None).unwrap();
    assert_duplicate_binaries(&db);
}

// ---- New attachments with the form (Step 102 п. 5): the bytes of all of them in one buffer, cut by the sizes ----

fn new_attachments(files: &[(&str, &[u8])]) -> (Vec<NewAttachment>, Vec<u8>) {
    let list = files
        .iter()
        .map(|(name, data)| NewAttachment {
            name: name.to_string(),
            size: data.len(),
        })
        .collect();
    (
        list,
        files.iter().flat_map(|(_, data)| data.to_vec()).collect(),
    )
}

fn new_entry_form(db: &Db, title: &str) -> (Uuid, Value) {
    let root_uuid = db_service::groups_summary_data(&db.0).unwrap().root_uuid;
    let form = db_service::new_entry_form_data(Some(&root_uuid));
    let mut v = serde_json::to_value(&form).unwrap();
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    common::form::set_field(&mut v, "Title", title);
    (uuid, v)
}

fn entry_form(db: &Db, entry: &Uuid) -> Value {
    serde_json::to_value(db_service::get_entry_form_data_by_id(&db.0, entry).unwrap()).unwrap()
}

fn insert_with(
    db: &Db,
    form: &Value,
    files: &[(&str, &[u8])],
) -> kdbx_rust_core::error::Result<()> {
    let (list, data) = new_attachments(files);
    db_service::insert_entry_from_form_data_with_attachments(
        &db.0,
        serde_json::from_value(form.clone()).unwrap(),
        &list,
        data,
    )
}

fn update_with(
    db: &Db,
    form: &Value,
    files: &[(&str, &[u8])],
) -> kdbx_rust_core::error::Result<()> {
    let (list, data) = new_attachments(files);
    db_service::update_entry_from_form_data_with_attachments(
        &db.0,
        serde_json::from_value(form.clone()).unwrap(),
        &list,
        data,
    )
}

fn named(files: &[(&str, &[u8])]) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .map(|(name, data)| (name.to_string(), data.to_vec()))
        .collect()
}

fn is_data_error<T: std::fmt::Debug>(result: kdbx_rust_core::error::Result<T>) -> bool {
    matches!(result, Err(kdbx_rust_core::error::Error::DataError(_)))
}

#[test]
fn new_attachments_come_with_the_form_of_a_new_entry() {
    let db = create_db("with_form_insert");
    let (entry, form) = new_entry_form(&db, "New");
    let files: &[(&str, &[u8])] = &[("a.txt", b"first"), ("empty", b""), ("b.bin", &[0, 1, 255])];

    insert_with(&db, &form, files).unwrap();
    assert_eq!(attachments_of(&db, &entry), named(files));

    save_and_reopen(&db);
    assert_eq!(attachments_of(&db, &entry), named(files));
}

#[test]
fn new_attachments_join_those_of_the_entry_and_the_version_keeps_the_old() {
    let db = create_db("with_form_update");
    let (entry, form) = new_entry_form(&db, "Edited");
    insert_with(&db, &form, &[("a.txt", b"first")]).unwrap();

    update_with(&db, &entry_form(&db, &entry), &[("b.txt", b"second")]).unwrap();
    save_and_reopen(&db);

    assert_eq!(
        attachments_of(&db, &entry),
        named(&[("a.txt", b"first"), ("b.txt", b"second")])
    );
    let version = db_service::history_entry_by_index(&db.0, &entry, 0).unwrap();
    let version = serde_json::to_value(&version).unwrap();
    let names: Vec<&str> = version["binary_key_values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["key"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["a.txt"]);
}

#[test]
fn sizes_that_do_not_cover_the_bytes_refuse_the_form() {
    let db = create_db("with_form_sizes");
    let (entry, form) = new_entry_form(&db, "Refused");
    let mut list = vec![NewAttachment {
        name: "a.txt".into(),
        size: 3,
    }];

    let short = db_service::insert_entry_from_form_data_with_attachments(
        &db.0,
        serde_json::from_value(form.clone()).unwrap(),
        &list,
        b"four".to_vec(),
    );
    assert!(is_data_error(short));
    list[0].size = 5;
    let long = db_service::insert_entry_from_form_data_with_attachments(
        &db.0,
        serde_json::from_value(form).unwrap(),
        &list,
        b"four".to_vec(),
    );
    assert!(is_data_error(long));

    // Nothing put in
    assert!(db_service::get_entry_form_data_by_id(&db.0, &entry).is_err());
}

#[test]
fn a_repeated_name_refuses_the_form() {
    let db = create_db("with_form_names");
    let (entry, form) = new_entry_form(&db, "Names");

    // Among the new ones
    assert!(is_data_error(insert_with(
        &db,
        &form,
        &[("a.txt", b"one"), ("a.txt", b"two")]
    )));
    // An empty name
    assert!(is_data_error(insert_with(&db, &form, &[("", b"one")])));

    // A new one with the name of one the entry has: the entry stays as it was
    insert_with(&db, &form, &[("a.txt", b"one")]).unwrap();
    assert!(is_data_error(update_with(
        &db,
        &entry_form(&db, &entry),
        &[("a.txt", b"two")]
    )));
    assert_eq!(attachments_of(&db, &entry), named(&[("a.txt", b"one")]));
}

#[test]
fn an_attachment_of_the_form_not_in_the_database_refuses_it() {
    let db = create_db("with_form_unknown");
    let (entry, form) = new_entry_form(&db, "Unknown");
    insert_with(&db, &form, &[("a.txt", b"one")]).unwrap();

    let mut edited = entry_form(&db, &entry);
    let hash = hash_of(&edited["binary_key_values"][0]);
    edited["binary_key_values"][0]["data_hash"] = json!(hash.wrapping_add(1).to_string());

    assert!(is_data_error(update_with(&db, &edited, &[])));
    assert_eq!(attachments_of(&db, &entry), named(&[("a.txt", b"one")]));
}

#[test]
fn the_size_of_an_attachment_of_the_form_is_that_of_its_bytes() {
    let db = create_db("with_form_size");
    let (entry, form) = new_entry_form(&db, "Size");
    insert_with(&db, &form, &[("a.txt", b"12345")]).unwrap();

    let mut edited = entry_form(&db, &entry);
    edited["binary_key_values"][0]["data_size"] = json!(999);
    update_with(&db, &edited, &[]).unwrap();

    assert_eq!(
        entry_form(&db, &entry)["binary_key_values"][0]["data_size"],
        json!(5)
    );
}

#[test]
fn an_attachment_left_out_of_the_form_is_gone_with_the_next_write() {
    let db = create_db("with_form_removed");
    let (entry, form) = new_entry_form(&db, "Removed");
    insert_with(&db, &form, &[("a.txt", b"one"), ("b.txt", b"two")]).unwrap();
    let mut edited = entry_form(&db, &entry);
    let removed = hash_of(&edited["binary_key_values"][1]);
    edited["binary_key_values"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    update_with(&db, &edited, &[]).unwrap();
    // The version still links it: gone once the history is too
    db_service::delete_history_entries(&db.0, &entry).unwrap();

    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();

    assert_eq!(attachments_of(&db, &entry), named(&[("a.txt", b"one")]));
    let mut out = vec![];
    assert!(db_service::save_attachment_to_writer(&db.0, &removed, &mut out).is_err());
}

#[test]
fn new_attachments_with_the_form_survive_a_lock() {
    let db = create_db("with_form_lock");
    let (entry, form) = new_entry_form(&db, "Locked");
    insert_with(&db, &form, &[("a.txt", b"one"), ("b.txt", b"two")]).unwrap();

    db_service::lock_kdbx(&db.0).unwrap();
    db_service::unlock_kdbx(&db.0, Some(PASSWORD), None).unwrap();

    assert_eq!(
        attachments_of(&db, &entry),
        named(&[("a.txt", b"one"), ("b.txt", b"two")])
    );
}
