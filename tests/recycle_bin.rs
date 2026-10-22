//! Корзина (Step 69): в корзину попадают только записи.
//!
//! Удаление смотрит на `Meta/RecycleBinEnabled`: включена — запись в корзину, группа — её записи в корзину плоско,
//! сами группы насовсем; выключена — всё насовсем, корзина не создаётся. Насовсем — значит в `DeletedObjects`.
//! Выключение корзины через `set_db_settings` удаляет её группу со всем содержимым. При переносе записи ставится
//! `PreviousParentGroup` (KDBX 4.1) — прежняя группа для восстановления.

mod common;

use common::xml::{parse_xml, Node};
use kdbx_rust_core::db_service::{self, DbSettings, NewDatabase};
use kdbx_rust_core::error::Error;
use serde_json::json;
use uuid::Uuid;

const PASSWORD: &str = "recycle-bin-1234";

struct Db(String);

impl Drop for Db {
    fn drop(&mut self) {
        let _ = db_service::close_kdbx(&self.0);
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_path(name: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("okp_recycle_bin_{}_{}", name, std::process::id()));
    p.to_str().unwrap().to_string()
}

// KDF уменьшен, чтобы тест был быстрым в debug
fn create_db(name: &str) -> Db {
    common::init();
    let db_key = temp_path(&format!("{}.kdbx", name));
    let _ = std::fs::remove_file(&db_key);

    let mut v = serde_json::to_value(NewDatabase::default()).unwrap();
    v["database_name"] = json!("RecycleBin");
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

fn bin(db: &Db) -> Uuid {
    db_service::groups_summary_data(&db.0)
        .unwrap()
        .recycle_bin_uuid
}

fn add_group(db: &Db, parent: Uuid, name: &str) -> Uuid {
    let group = db_service::new_blank_group_with_parent(parent, false).unwrap();
    let mut v = serde_json::to_value(&group).unwrap();
    v["name"] = json!(name);
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    db_service::insert_group(&db.0, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

fn add_entry(db: &Db, group: Uuid, title: &str) -> Uuid {
    let form = db_service::new_entry_form_data(Some(&group));
    let mut v = serde_json::to_value(&form).unwrap();
    common::form::set_field(&mut v, "Title", title);
    let uuid = Uuid::parse_str(v["uuid"].as_str().unwrap()).unwrap();
    db_service::insert_entry_from_form_data(&db.0, serde_json::from_value(v).unwrap()).unwrap();
    uuid
}

// Группа записи; None — записи в базе нет
fn parent_of(db: &Db, entry: Uuid) -> Option<Uuid> {
    let form = db_service::get_entry_form_data_by_id(&db.0, &entry).ok()?;
    let v = serde_json::to_value(form).unwrap();
    Some(Uuid::parse_str(v["group_uuid"].as_str().unwrap()).unwrap())
}

fn group_exists(db: &Db, group: Uuid) -> bool {
    db_service::get_group_by_id(&db.0, &group).is_ok()
}

fn bin_enabled(db: &Db) -> bool {
    let v = serde_json::to_value(db_service::get_db_settings(&db.0).unwrap()).unwrap();
    v["meta"]["recycle_bin_enabled"].as_bool().unwrap()
}

// Тогл экрана: настройки как их видит клиент, флаг изменён
fn set_bin_enabled(db: &Db, enabled: bool) {
    let mut v = serde_json::to_value(db_service::get_db_settings(&db.0).unwrap()).unwrap();
    v["meta"]["recycle_bin_enabled"] = json!(enabled);
    let settings: DbSettings = serde_json::from_value(v).unwrap();
    db_service::set_db_settings(&db.0, settings, None).unwrap();
}

fn save_and_reopen(db: &Db) {
    db_service::save_kdbx_with_backup(&db.0, None, false).unwrap();
    db_service::close_kdbx(&db.0).unwrap();
    db_service::load_kdbx(&db.0, Some(PASSWORD), None).unwrap();
}

fn export_xml(db: &Db) -> Node {
    // Своё имя на базу: тесты идут параллельно
    let xml_path = format!("{}.xml", db.0);
    db_service::export_as_xml(&db.0, &xml_path).unwrap();
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    parse_xml(&xml)
}

fn base64_uuid(uuid: &Uuid) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes())
}

fn find_tag<'a>(node: &'a Node, tag: &str) -> Option<&'a Node> {
    if node.tag == tag {
        return Some(node);
    }
    node.children.iter().find_map(|c| find_tag(c, tag))
}

// UUID из `Root/DeletedObjects`, как в файле (base64)
fn deleted_objects(xml: &Node) -> Vec<String> {
    find_tag(xml, "DeletedObjects")
        .map(|d| {
            d.children
                .iter()
                .filter_map(|o| o.text_of("UUID").map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn assert_deleted_for_good(xml: &Node, uuid: &Uuid, what: &str) {
    assert!(
        deleted_objects(xml).contains(&base64_uuid(uuid)),
        "{} нет в DeletedObjects",
        what
    );
}

// Как KeePass: в новой базе корзина включена
#[test]
fn a_new_database_has_the_recycle_bin_on() {
    let db = create_db("new");
    assert!(bin_enabled(&db));
}

#[test]
fn an_entry_goes_to_the_bin_with_its_previous_group_in_the_file() {
    let db = create_db("entry_to_bin");
    let work = add_group(&db, root(&db), "Work");
    let entry = add_entry(&db, work, "Mail");

    db_service::delete_entry(&db.0, entry).unwrap();
    assert_ne!(bin(&db), Uuid::default(), "корзина не создана");
    assert_eq!(parent_of(&db, entry), Some(bin(&db)));

    save_and_reopen(&db);
    assert_eq!(parent_of(&db, entry), Some(bin(&db)));
    let xml = export_xml(&db);
    let node = xml
        .find_by_uuid("Entry", &base64_uuid(&entry))
        .expect("записи нет в файле");
    assert_eq!(
        node.text_of("PreviousParentGroup"),
        Some(base64_uuid(&work).as_str())
    );
    assert!(!deleted_objects(&xml).contains(&base64_uuid(&entry)));
}

#[test]
fn a_group_sends_its_entries_to_the_bin_flat_and_is_removed_for_good() {
    let db = create_db("group_to_bin");
    let work = add_group(&db, root(&db), "Work");
    let inner = add_group(&db, work, "Inner");
    let mail = add_entry(&db, work, "Mail");
    let jira = add_entry(&db, inner, "Jira");

    db_service::delete_group(&db.0, work).unwrap();

    let bin = bin(&db);
    assert!(!group_exists(&db, work));
    assert!(!group_exists(&db, inner));
    assert_eq!(parent_of(&db, mail), Some(bin));
    assert_eq!(parent_of(&db, jira), Some(bin));
    let bin_group = db_service::get_group_by_id(&db.0, &bin).unwrap();
    let bin_group = serde_json::to_value(bin_group).unwrap();
    assert!(
        bin_group["group_uuids"].as_array().unwrap().is_empty(),
        "в корзине группа"
    );

    save_and_reopen(&db);
    let xml = export_xml(&db);
    assert_deleted_for_good(&xml, &work, "группы");
    assert_deleted_for_good(&xml, &inner, "подгруппы");
    let jira_node = xml.find_by_uuid("Entry", &base64_uuid(&jira)).unwrap();
    assert_eq!(
        jira_node.text_of("PreviousParentGroup"),
        Some(base64_uuid(&inner).as_str())
    );
}

#[test]
fn with_the_bin_off_an_entry_is_removed_for_good_and_no_bin_is_made() {
    let db = create_db("entry_off");
    let entry = add_entry(&db, root(&db), "Mail");
    set_bin_enabled(&db, false);

    db_service::delete_entry(&db.0, entry).unwrap();

    assert_eq!(parent_of(&db, entry), None);
    assert_eq!(bin(&db), Uuid::default(), "корзина создана");
    save_and_reopen(&db);
    assert!(!bin_enabled(&db));
    assert_deleted_for_good(&export_xml(&db), &entry, "записи");
}

#[test]
fn with_the_bin_off_a_group_is_removed_with_its_entries() {
    let db = create_db("group_off");
    let work = add_group(&db, root(&db), "Work");
    let inner = add_group(&db, work, "Inner");
    let jira = add_entry(&db, inner, "Jira");
    set_bin_enabled(&db, false);

    db_service::delete_group(&db.0, work).unwrap();

    assert!(!group_exists(&db, work));
    assert!(!group_exists(&db, inner));
    assert_eq!(parent_of(&db, jira), None);
    assert_eq!(bin(&db), Uuid::default());
    let xml = export_xml(&db);
    for (uuid, what) in [(work, "группы"), (inner, "подгруппы"), (jira, "записи")]
    {
        assert_deleted_for_good(&xml, &uuid, what);
    }
}

#[test]
fn switching_the_bin_off_removes_it_with_all_it_holds() {
    let db = create_db("switch_off");
    let kept = add_entry(&db, root(&db), "Kept");
    let binned = add_entry(&db, root(&db), "Binned");
    db_service::delete_entry(&db.0, binned).unwrap();
    let old_bin = bin(&db);

    set_bin_enabled(&db, false);

    assert!(!bin_enabled(&db));
    assert_eq!(bin(&db), Uuid::default());
    assert!(!group_exists(&db, old_bin));
    assert_eq!(parent_of(&db, binned), None);
    assert_eq!(parent_of(&db, kept), Some(root(&db)));

    save_and_reopen(&db);
    assert!(!bin_enabled(&db));
    assert_eq!(bin(&db), Uuid::default());
    let xml = export_xml(&db);
    assert_eq!(
        find_tag(&xml, "RecycleBinUUID").map(|n| n.text.as_str()),
        Some(base64_uuid(&Uuid::default()).as_str())
    );
    assert_deleted_for_good(&xml, &old_bin, "корзины");
    assert_deleted_for_good(&xml, &binned, "записи из корзины");
}

#[test]
fn switched_on_again_the_first_delete_makes_a_new_bin() {
    let db = create_db("switch_on");
    let first = add_entry(&db, root(&db), "First");
    db_service::delete_entry(&db.0, first).unwrap();
    let old_bin = bin(&db);
    set_bin_enabled(&db, false);
    set_bin_enabled(&db, true);
    assert_eq!(bin(&db), Uuid::default(), "корзина до первого удаления");

    let second = add_entry(&db, root(&db), "Second");
    db_service::delete_entry(&db.0, second).unwrap();

    let new_bin = bin(&db);
    assert_ne!(new_bin, Uuid::default());
    assert_ne!(new_bin, old_bin);
    assert_eq!(parent_of(&db, second), Some(new_bin));
    save_and_reopen(&db);
    assert!(bin_enabled(&db));
    assert_eq!(bin(&db), new_bin);
}

// Остальные настройки не трогают корзину: флаг не меняется — корзина на месте
#[test]
fn other_settings_keep_the_bin() {
    let db = create_db("other_settings");
    let binned = add_entry(&db, root(&db), "Binned");
    db_service::delete_entry(&db.0, binned).unwrap();

    set_bin_enabled(&db, true);

    assert_eq!(parent_of(&db, binned), Some(bin(&db)));
}

#[test]
fn the_root_the_bin_and_an_entry_in_the_bin_are_not_deleted() {
    let db = create_db("refused");
    let root = root(&db);
    let binned = add_entry(&db, root, "Binned");
    db_service::delete_entry(&db.0, binned).unwrap();
    let bin = bin(&db);

    assert!(db_service::delete_entry(&db.0, binned).is_err());
    assert!(db_service::delete_group(&db.0, root).is_err());
    assert!(db_service::delete_group(&db.0, bin).is_err());

    assert!(group_exists(&db, root));
    assert!(group_exists(&db, bin));
    assert_eq!(parent_of(&db, binned), Some(bin));
}

#[test]
fn an_unknown_uuid_is_not_found() {
    let db = create_db("unknown");
    assert!(matches!(
        db_service::delete_entry(&db.0, Uuid::new_v4()),
        Err(Error::NotFound(_))
    ));
    assert!(matches!(
        db_service::delete_group(&db.0, Uuid::new_v4()),
        Err(Error::NotFound(_))
    ));
}
