//! Неизвестные элементы переживают слияние двух чужих баз (Step 18, п.3).
//!
//! Сохранение — не единственный путь, на котором данные чужого клиента могут пропасть:
//! при merge запись и группа берутся из более новой базы (`Group::assign_merge_properties`,
//! клонирование записи в `db_merge::merger`), и всё, что ядро не показывает, должно
//! переехать вместе с ними.
//!
//! Фикстура `unknown_everywhere_41.kdbx` — та же, что в `unknown_elements_preservation.rs`:
//! незнакомый тег на каждом уровне дерева. Сценарий: две копии одной чужой базы, в источнике
//! запись и группа помечены как более новые → merge → сохранить → открыть → все элементы на
//! месте. Так проверяется путь слияния целиком, а не только юнит-тест `assign_merge_properties`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use common::xml::{parse_xml, Node};
use onekeepass_core::db_service;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "unknown_everywhere_41.kdbx";

const GROUP: &str = "ex5cYAAAQACAAAAAAAAAAQ==";
const ENTRY: &str = "ex5cYAAAQACAAAAAAAAAEA==";

// Все неизвестные теги фикстуры (UNK_TAGS в генераторе) и путь, где каждый стоит.
const EXPECTED: &[(&[&str], &str)] = &[
    (&[], "XFileUnknown"),
    (&["Meta"], "XMetaUnknown"),
    (&["Meta", "MemoryProtection"], "XProtectUnknown"),
    (&["Meta", "CustomIcons"], "XIconsUnknown"),
    (&["Meta", "CustomIcons", "Icon"], "XIconUnknown"),
    (&["Root"], "XRootUnknown"),
    (&["Root", "DeletedObjects"], "XDeletedObjectsUnknown"),
    (
        &["Root", "DeletedObjects", "DeletedObject"],
        "XDeletedObjectUnknown",
    ),
];

static SEQ: AtomicU64 = AtomicU64::new(0);

fn resource(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("resources");
    path.push(name);
    path
}

fn temp_path(suffix: &str) -> String {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut target = std::env::temp_dir();
    target.push(format!(
        "okp_unkmerge_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    target.to_str().unwrap().to_string()
}

fn copy_fixture(suffix: &str) -> String {
    let path = temp_path(suffix);
    std::fs::copy(resource(FIXTURE), &path).unwrap();
    path
}

fn open(db_key: &str) {
    db_service::load_kdbx(db_key, Some(PASSWORD), None)
        .unwrap_or_else(|e| panic!("не удалось открыть {}: {:?}", db_key, e));
}

fn close(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

fn export_xml(db_key: &str) -> Node {
    let xml_path = temp_path("dump.xml");
    db_service::export_as_xml(db_key, &xml_path).expect("выгрузка XML не удалась");
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    parse_xml(&xml)
}

/// Слить копию фикстуры в другую копию и вернуть XML результата.
fn merged_xml() -> Node {
    common::init();
    let target = copy_fixture("target.kdbx");
    let source = copy_fixture("source.kdbx");

    open(&target);
    open(&source);

    db_service::merge_databases(&target, &source, Some(PASSWORD), None)
        .expect("слияние не удалось");
    close(&source);

    let saved = temp_path("merged.kdbx");
    db_service::save_to_db_file(&target, &saved).expect("сохранение результата не удалось");
    close(&target);

    open(&saved);
    let xml = export_xml(&saved);
    close(&saved);
    xml
}

fn at<'a>(xml: &'a Node, path: &[&str]) -> &'a Node {
    xml.at(path)
        .unwrap_or_else(|| panic!("путь {:?} не найден после слияния", path))
}

/// Элементы уровня файла, Meta и Root: их владельцы при слиянии не пересоздаются,
/// но и потерять их нельзя.
#[test]
fn unknown_elements_of_file_meta_and_root_survive_merge() {
    let xml = merged_xml();

    for (path, tag) in EXPECTED {
        let parent = at(&xml, path);
        assert!(
            parent.child(tag).is_some(),
            "{:?}: <{}> потерян при слиянии",
            path,
            tag
        );
    }
}

/// Группа и запись — то, что merge действительно переносит из более новой базы.
#[test]
fn unknown_elements_of_group_and_entry_survive_merge() {
    let xml = merged_xml();

    let group = xml.find_by_uuid("Group", GROUP).expect("группа потеряна");
    assert!(
        group.child("XGroupUnknown").is_some(),
        "группа: <XGroupUnknown> потерян при слиянии"
    );
    assert!(
        at(group, &["Times"]).child("XGroupTimesUnknown").is_some(),
        "группа: <XGroupTimesUnknown> внутри Times потерян при слиянии"
    );

    let entry = xml.find_by_uuid("Entry", ENTRY).expect("запись потеряна");
    assert!(
        entry.child("XEntryUnknown").is_some(),
        "запись: <XEntryUnknown> потерян при слиянии"
    );
    assert!(
        at(entry, &["Times"]).child("XEntryTimesUnknown").is_some(),
        "запись: <XEntryTimesUnknown> внутри Times потерян при слиянии"
    );
    assert!(
        at(entry, &["AutoType", "Association"])
            .child("XAssociationUnknown")
            .is_some(),
        "запись: <XAssociationUnknown> внутри Association потерян при слиянии"
    );

    // Версия в истории переносится вместе с записью
    let history_entry = at(entry, &["History", "Entry"]);
    assert!(
        history_entry.child("XHistoryEntryUnknown").is_some(),
        "история: <XHistoryEntryUnknown> потерян при слиянии"
    );
    assert!(
        at(history_entry, &["Times"])
            .child("XHistoryTimesUnknown")
            .is_some(),
        "история: <XHistoryTimesUnknown> внутри Times потерян при слиянии"
    );
}
