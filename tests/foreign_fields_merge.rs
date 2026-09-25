//! Поля чужих клиентов переживают слияние двух баз (Step 19, п.7).
//!
//! Step 17 научил ядро читать и писать то, что наш UI не показывает: цвета записи,
//! `OverrideURL`, флаг проверки качества пароля, трёхзначные флаги группы, ссылку на
//! прежнего родителя. Сохранение такие поля переживают (`tests/all_fields_preservation.rs`),
//! но есть второй путь, на котором их можно потерять, — слияние: объект берётся из более
//! новой базы (`Group::assign_merge_properties`, клонирование записи в `db_merge::merger`).
//!
//! Здесь сквозная проверка всего пути на фикстуре `all_fields_41.kdbx`: открыть две копии,
//! слить, сохранить, открыть результат. Точный тест самого переноса (в источнике поля есть,
//! в цели нет) — `db_merge::merge_tests::verify_foreign_fields_of_newer_source_are_merged_in`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use common::xml::{parse_xml, Node};
use kdbx_rust_core::db_service;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "all_fields_41.kdbx";

// UUID объектов фикстуры (AF_UUIDS в генераторе) в виде, как они лежат в XML — base64.
const WORK: &str = "Wg46TgAAQACAAAAAAAAAAQ==";
const TEMPLATES: &str = "Wg46TgAAQACAAAAAAAAAAg==";
const ENTRY: &str = "Wg46TgAAQACAAAAAAAAAEA==";

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
        "okp_ffmerge_{}_{}_{}",
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

/// XML результата слияния двух копий фикстуры после сохранения и повторного открытия.
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
    let xml_path = temp_path("dump.xml");
    db_service::export_as_xml(&saved, &xml_path).expect("выгрузка XML не удалась");
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    close(&saved);
    parse_xml(&xml)
}

fn assert_text(node: &Node, tag: &str, expected: &str, what: &str) {
    assert_eq!(
        node.text_of(tag),
        Some(expected),
        "{}: <{}> потерян или изменён при слиянии",
        what,
        tag
    );
}

#[test]
fn entry_fields_survive_merge() {
    let xml = merged_xml();
    let entry = xml.find_by_uuid("Entry", ENTRY).expect("запись потеряна");

    for (tag, expected) in [
        ("ForegroundColor", "#112233"),
        ("BackgroundColor", "#445566"),
        ("OverrideURL", "cmd://firefox {URL}"),
        ("QualityCheck", "False"),
        ("PreviousParentGroup", TEMPLATES),
        ("Tags", "alpha;beta&gamma"),
        ("IconID", "12"),
    ] {
        assert_text(entry, tag, expected, "запись");
    }

    let auto_type = entry.child("AutoType").expect("запись: <AutoType> потерян");
    assert_text(auto_type, "DataTransferObfuscation", "1", "запись/AutoType");
    assert_text(
        auto_type,
        "DefaultSequence",
        "{PASSWORD}{ENTER}",
        "запись/AutoType",
    );
}

#[test]
fn group_fields_survive_merge() {
    let xml = merged_xml();
    let work = xml
        .find_by_uuid("Group", WORK)
        .expect("группа Work потеряна");

    for (tag, expected) in [
        ("DefaultAutoTypeSequence", "{USERNAME}{ENTER}"),
        ("EnableAutoType", "False"),
        ("EnableSearching", "False"),
        ("IsExpanded", "False"),
        ("PreviousParentGroup", TEMPLATES),
        ("Tags", "g1,g2"),
        ("Notes", "work group notes"),
    ] {
        assert_text(work, tag, expected, "группа Work");
    }
}

/// Неизвестные элементы Step 18 на тех же объектах — слияние не должно их терять
/// (их отдельная фикстура — `tests/unknown_elements_merge.rs`).
#[test]
fn unknown_elements_of_all_fields_survive_merge() {
    let xml = merged_xml();

    for (tag, uuid) in [("Group", WORK), ("Entry", ENTRY)] {
        let node = xml
            .find_by_uuid(tag, uuid)
            .unwrap_or_else(|| panic!("{} потерян", tag));
        assert!(
            node.child("XPassholderUnknown").is_some(),
            "{}: неизвестный элемент потерян при слиянии",
            tag
        );
    }
}
