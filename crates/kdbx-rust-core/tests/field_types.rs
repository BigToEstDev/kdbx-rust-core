//! Типы своих полей записи (Step 76).
//!
//! Тип поля — логика приложения (телефон, …), не KDBX: ядро держит его в `CustomData` записи под одним своим
//! ключом `PassHolder.FieldTypes` — JSON, имя поля → тип; текстовое поле не пишется, нет типизированных полей —
//! нет ключа. В форме тип — `field_type` у поля. Ядро тип не толкует: незнакомый проходит как пришёл. Остальной
//! `CustomData` — как прочитан (Step 43): здесь это `OKP_K3` фикстуры `okp_entry_types.kdbx`.
//!
//! Путь целиком: форма → файл → переоткрытие → форма; история, клон и слияние несут тип вместе с записью.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use common::xml::{parse_xml, Node};
use kdbx_rust_core::db_service::{self, EntryCategory, EntryCloneOption, EntryFormData};
use serde_json::{json, Value};
use uuid::Uuid;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "okp_entry_types.kdbx";
const ENTRY: &str = "My SFTP";
const KEY: &str = "PassHolder.FieldTypes";
const OKP_ENTRY_TYPE_KEY: &str = "OKP_K3";

static SEQ: AtomicU64 = AtomicU64::new(0);

struct Db(String);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = db_service::close_kdbx(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_path(suffix: &str) -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_field_types_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    target.to_str().unwrap().to_string()
}

fn copy_fixture(suffix: &str) -> Db {
    common::init();
    let mut source = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source.push("tests/resources");
    source.push(FIXTURE);
    let db = Db(temp_path(suffix));
    std::fs::copy(source, &db.0).unwrap();
    db
}

fn open(db: &Db) {
    db_service::load_kdbx(&db.0, Some(PASSWORD), None)
        .unwrap_or_else(|e| panic!("не удалось открыть {}: {:?}", db.0, e));
}

fn open_copy(suffix: &str) -> Db {
    let db = copy_fixture(suffix);
    open(&db);
    db
}

fn save_and_reopen(db: &Db) {
    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();
    db_service::close_kdbx(&db.0).unwrap();
    open(db);
}

fn entry_uuid(db: &Db, title: &str) -> Uuid {
    let entries = db_service::entry_summary_data(&db.0, EntryCategory::AllEntries).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.title.as_deref() == Some(title))
        .unwrap_or_else(|| panic!("запись {} не найдена", title));
    Uuid::parse_str(&entry.uuid).unwrap()
}

fn form(db: &Db, uuid: Uuid) -> Value {
    serde_json::to_value(db_service::get_entry_form_data_by_id(&db.0, &uuid).unwrap()).unwrap()
}

/// Ставит полю формы тип; `None` — текст. Поля нет — добавляет его.
fn set_type(form: &mut Value, key: &str, field_type: Option<&str>) {
    if common::form::field(form, key).is_none() {
        common::form::set_field(form, key, "+7 900 000-00-00");
    }
    let fields = form["fields"].as_array_mut().unwrap();
    let f = fields.iter_mut().find(|f| f["key"] == key).unwrap();
    f["field_type"] = json!(field_type);
}

fn type_of<'a>(form: &'a Value, key: &str) -> Option<&'a str> {
    form["fields"]
        .as_array()?
        .iter()
        .find(|f| f["key"] == key)
        .and_then(|f| f["field_type"].as_str())
}

fn update(db: &Db, form: Value) {
    let form: EntryFormData = serde_json::from_value(form).unwrap();
    db_service::update_entry_from_form_data(&db.0, form).unwrap();
}

fn export_xml(db: &Db) -> Node {
    let xml_path = temp_path("dump.xml");
    db_service::export_as_xml(&db.0, &xml_path).unwrap();
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    parse_xml(&xml)
}

fn base64_uuid(uuid: &Uuid) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes())
}

/// Значение ключа `CustomData` записи, как оно лежит в файле.
fn custom_data_value(db: &Db, uuid: Uuid, key: &str) -> Option<String> {
    let xml = export_xml(db);
    let entry = xml
        .find_by_uuid("Entry", &base64_uuid(&uuid))
        .expect("запись в XML");
    entry
        .child("CustomData")
        .and_then(|cd| cd.child_with("Item", "Key", key))
        .and_then(|item| item.text_of("Value"))
        .map(str::to_string)
}

#[test]
fn a_field_type_survives_the_file_next_to_foreign_custom_data() {
    let db = open_copy("survives.kdbx");
    let uuid = entry_uuid(&db, ENTRY);
    let okp = custom_data_value(&db, uuid, OKP_ENTRY_TYPE_KEY);
    assert!(
        okp.is_some(),
        "у записи фикстуры есть {}",
        OKP_ENTRY_TYPE_KEY
    );
    assert!(custom_data_value(&db, uuid, KEY).is_none());

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    set_type(&mut v, "Card", Some("from-a-newer-client"));
    update(&db, v);
    save_and_reopen(&db);

    let v = form(&db, uuid);
    assert_eq!(type_of(&v, "Phone"), Some("phone"));
    assert_eq!(type_of(&v, "Card"), Some("from-a-newer-client"));
    assert_eq!(type_of(&v, "Title"), None);
    assert_eq!(
        custom_data_value(&db, uuid, KEY).as_deref(),
        Some(r#"{"Card":"from-a-newer-client","Phone":"phone"}"#)
    );
    assert_eq!(custom_data_value(&db, uuid, OKP_ENTRY_TYPE_KEY), okp);
}

#[test]
fn text_fields_only_leave_no_key_and_foreign_custom_data_stays() {
    let db = open_copy("text_only.kdbx");
    let uuid = entry_uuid(&db, ENTRY);
    let okp = custom_data_value(&db, uuid, OKP_ENTRY_TYPE_KEY);

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    update(&db, v);

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", None);
    update(&db, v);
    save_and_reopen(&db);

    assert_eq!(type_of(&form(&db, uuid), "Phone"), None);
    assert!(custom_data_value(&db, uuid, KEY).is_none());
    assert_eq!(custom_data_value(&db, uuid, OKP_ENTRY_TYPE_KEY), okp);
}

#[test]
fn a_renamed_or_deleted_field_takes_its_type_along() {
    let db = open_copy("rename.kdbx");
    let uuid = entry_uuid(&db, ENTRY);

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    set_type(&mut v, "Fax", Some("phone"));
    update(&db, v);

    // Переименование — у поля формы другое имя, тип при нём; удалённого поля в форме нет
    let mut v = form(&db, uuid);
    let fields = v["fields"].as_array_mut().unwrap();
    fields.iter_mut().find(|f| f["key"] == "Phone").unwrap()["key"] = json!("Mobile");
    fields.retain(|f| f["key"] != "Fax");
    update(&db, v);
    save_and_reopen(&db);

    let v = form(&db, uuid);
    assert_eq!(type_of(&v, "Mobile"), Some("phone"));
    assert_eq!(
        custom_data_value(&db, uuid, KEY).as_deref(),
        Some(r#"{"Mobile":"phone"}"#)
    );
}

#[test]
fn history_keeps_the_type_a_version_had() {
    let db = open_copy("history.kdbx");
    let uuid = entry_uuid(&db, ENTRY);

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    update(&db, v);
    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("card"));
    update(&db, v);
    save_and_reopen(&db);

    let summary = db_service::history_entries_summary(&db.0, &uuid).unwrap();
    let last = summary.len() as i32 - 1;
    let version = db_service::history_entry_by_index(&db.0, &uuid, last).unwrap();
    let version = serde_json::to_value(version).unwrap();
    assert_eq!(type_of(&version, "Phone"), Some("phone"));
    assert_eq!(type_of(&form(&db, uuid), "Phone"), Some("card"));
}

#[test]
fn a_clone_has_the_types() {
    let db = open_copy("clone.kdbx");
    let uuid = entry_uuid(&db, ENTRY);

    let mut v = form(&db, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    let group = Uuid::parse_str(v["group_uuid"].as_str().unwrap()).unwrap();
    update(&db, v);

    let option = EntryCloneOption {
        new_title: Some("Clone".into()),
        parent_group_uuid: group,
        keep_histories: false,
        link_by_reference: false,
    };
    let clone = db_service::clone_entry(&db.0, &uuid, &option).unwrap();
    save_and_reopen(&db);

    assert_eq!(type_of(&form(&db, clone), "Phone"), Some("phone"));
}

/// Слияние: запись источника новее — приходит целиком, с типами.
#[test]
fn a_newer_entry_brings_its_types_into_a_merge() {
    let target = open_copy("merge_target.kdbx");
    let source = open_copy("merge_source.kdbx");
    let uuid = entry_uuid(&source, ENTRY);

    let mut v = form(&source, uuid);
    set_type(&mut v, "Phone", Some("phone"));
    update(&source, v);
    db_service::save_kdbx_with_backup(&source.0, None, false).unwrap();

    db_service::merge_databases(&target.0, &source.0, Some(PASSWORD), None).unwrap();
    let saved = Db(temp_path("merged.kdbx"));
    db_service::save_to_db_file(&target.0, &saved.0).unwrap();
    open(&saved);

    assert_eq!(type_of(&form(&saved, uuid), "Phone"), Some("phone"));
}
