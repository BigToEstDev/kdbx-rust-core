//! Сохранность чужих данных: каждый элемент KDBX 4.1 переживает сохранение (Step 17).
//!
//! Приложение работает в первую очередь с базами KeePass / KeePassXC / KeePassDX.
//! Если ядро при сохранении теряет или меняет поле, которого не показывает, пользователь
//! узнает об этом только в другом клиенте.
//!
//! Фикстура `all_fields_41.kdbx` собрана сторонней реализацией (pykeepass,
//! `tools/kdbx-oracle/gen_fixtures.py`, `build_all_fields_fixture`): каждый элемент
//! заполнен не значением по умолчанию. Значения ниже продублированы оттуда — менять
//! вместе. Полное сравнение до / после — `tools/kdbx-oracle/compare_roundtrip.py`.
//!
//! Сценарий: открыть фикстуру → сохранить в новый файл → открыть его → выгрузить XML
//! (`export_as_xml`, protected-значения там открытым текстом) → проверить элементы.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use onekeepass_core::db_service;
use quick_xml::events::Event;
use quick_xml::Reader;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "all_fields_41.kdbx";

// UUID объектов фикстуры (AF_UUIDS в генераторе) в виде, как они лежат в XML — base64.
const WORK: &str = "Wg46TgAAQACAAAAAAAAAAQ==";
const TEMPLATES: &str = "Wg46TgAAQACAAAAAAAAAAg==";
const RECYCLE_BIN: &str = "Wg46TgAAQACAAAAAAAAAAw==";
const ENTRY: &str = "Wg46TgAAQACAAAAAAAAAEA==";

// Неизвестный KDBX 4.1 элемент (AF_UNKNOWN_* в генераторе).
const UNKNOWN_TAG: &str = "XPassholderUnknown";

static SEQ: AtomicU64 = AtomicU64::new(0);

// --- минимальное XML-дерево для проверок ------------------------------------------

#[derive(Debug, Default)]
struct Node {
    tag: String,
    attrs: Vec<(String, String)>,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, tag: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.tag == tag)
    }

    fn text_of(&self, tag: &str) -> Option<&str> {
        self.child(tag).map(|c| c.text.as_str())
    }

    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Первый (в порядке документа) объект `tag` с `<UUID>` = `uuid`. Основная запись
    /// идёт раньше своей истории, поэтому для записи это всегда текущая версия.
    fn find_by_uuid(&self, tag: &str, uuid: &str) -> Option<&Node> {
        if self.tag == tag && self.text_of("UUID") == Some(uuid) {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find_by_uuid(tag, uuid))
    }

    /// Значение строкового поля записи `<String><Key>key</Key><Value>…</Value></String>`.
    fn string_field(&self, key: &str) -> Option<&Node> {
        self.children
            .iter()
            .filter(|c| c.tag == "String")
            .find(|c| c.text_of("Key") == Some(key))
            .and_then(|c| c.child("Value"))
    }
}

fn parse_xml(xml: &str) -> Node {
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<Node> = vec![Node::default()];
    loop {
        match reader.read_event().expect("XML не разбирается") {
            Event::Start(e) => stack.push(start_node(&e)),
            Event::Empty(e) => {
                let node = start_node(&e);
                stack.last_mut().unwrap().children.push(node);
            }
            Event::Text(t) => {
                let text = t.decode().unwrap();
                stack.last_mut().unwrap().text.push_str(&text);
            }
            Event::GeneralRef(r) => {
                // Сущности (&amp; и т.п.) приходят отдельным событием с quick-xml 0.38.
                let name = r.decode().unwrap();
                let resolved = quick_xml::escape::unescape(&format!("&{};", name))
                    .unwrap()
                    .into_owned();
                stack.last_mut().unwrap().text.push_str(&resolved);
            }
            Event::End(_) => {
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().children.push(node);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let mut document = stack.pop().unwrap();
    document.children.pop().expect("пустой XML")
}

fn start_node(e: &quick_xml::events::BytesStart) -> Node {
    Node {
        tag: String::from_utf8(e.name().as_ref().to_vec()).unwrap(),
        attrs: e
            .attributes()
            .map(|a| {
                let a = a.unwrap();
                (
                    String::from_utf8(a.key.as_ref().to_vec()).unwrap(),
                    String::from_utf8(a.value.to_vec()).unwrap(),
                )
            })
            .collect(),
        ..Default::default()
    }
}

// --- открыть, сохранить, выгрузить --------------------------------------------------

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
        "okp_allfields_{}_{}_{}",
        std::process::id(),
        seq,
        suffix
    ));
    target.to_str().unwrap().to_string()
}

fn open(db_key: &str) {
    db_service::load_kdbx(db_key, Some(PASSWORD), None)
        .unwrap_or_else(|e| panic!("не удалось открыть {}: {:?}", db_key, e));
}

fn export_xml(db_key: &str) -> Node {
    let xml_path = temp_path("dump.xml");
    db_service::export_as_xml(db_key, &xml_path).expect("выгрузка XML не удалась");
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    parse_xml(&xml)
}

fn close(db_key: &str) {
    let _ = db_service::close_kdbx(db_key);
    let _ = std::fs::remove_file(db_key);
}

/// XML базы после одного цикла «открыть чужой файл → сохранить → открыть сохранённое».
fn saved_xml() -> Node {
    common::init();
    let source = temp_path(FIXTURE);
    std::fs::copy(resource(FIXTURE), &source).unwrap();
    open(&source);

    let saved = temp_path("saved.kdbx");
    db_service::save_to_db_file(&source, &saved).expect("сохранение в новый файл не удалось");
    close(&source);

    open(&saved);
    let xml = export_xml(&saved);
    close(&saved);
    xml
}

fn assert_text(node: &Node, tag: &str, expected: &str, what: &str) {
    assert_eq!(
        node.text_of(tag),
        Some(expected),
        "{}: <{}> потерян или изменён",
        what,
        tag
    );
}

fn root_group(xml: &Node) -> &Node {
    xml.child("Root").unwrap().child("Group").unwrap()
}

// --- тесты --------------------------------------------------------------------------

#[test]
fn meta_fields_survive_save() {
    let xml = saved_xml();
    let meta = xml.child("Meta").unwrap();

    for (tag, expected) in [
        ("Color", "#FF8800"),
        ("LastSelectedGroup", WORK),
        ("LastTopVisibleGroup", TEMPLATES),
        // 2021-03-06 10:20:30 UTC — af_time(kp, 6) в генераторе
        ("RecycleBinChanged", "bk7V1w4AAAA="),
        ("MasterKeyChangeRec", "90"),
        ("MasterKeyChangeForce", "180"),
        ("MasterKeyChangeForceOnce", "True"),
        // уже сохранялись до Step 17 — страховка от регрессии
        ("MaintenanceHistoryDays", "123"),
        ("HistoryMaxItems", "7"),
        ("DefaultUserName", "default-user"),
    ] {
        assert_text(meta, tag, expected, "Meta");
    }

    let protection = meta
        .child("MemoryProtection")
        .expect("Meta: <MemoryProtection> потерян");
    for (tag, expected) in [
        ("ProtectTitle", "True"),
        ("ProtectUserName", "True"),
        ("ProtectPassword", "False"),
        ("ProtectURL", "True"),
        ("ProtectNotes", "True"),
    ] {
        assert_text(protection, tag, expected, "Meta/MemoryProtection");
    }
}

/// Корзина выключена в KeePass, группа-корзина осталась — после нашего сохранения
/// она не должна включиться обратно (иначе KeePass начнёт перемещать удалённое в неё).
#[test]
fn disabled_recycle_bin_stays_disabled() {
    let xml = saved_xml();
    let meta = xml.child("Meta").unwrap();
    assert_text(meta, "RecycleBinEnabled", "False", "Meta");
    assert_text(meta, "RecycleBinUUID", RECYCLE_BIN, "Meta");
}

#[test]
fn group_fields_survive_save() {
    let xml = saved_xml();

    let work = xml
        .find_by_uuid("Group", WORK)
        .expect("группа Work потеряна");
    for (tag, expected) in [
        ("DefaultAutoTypeSequence", "{USERNAME}{ENTER}"),
        ("EnableAutoType", "False"),
        ("EnableSearching", "False"),
        ("LastTopVisibleEntry", ENTRY),
        ("PreviousParentGroup", TEMPLATES),
        ("IsExpanded", "False"),
        // уже сохранялись до Step 17
        ("Tags", "g1,g2"),
        ("Notes", "work group notes"),
    ] {
        assert_text(work, tag, expected, "Group Work");
    }

    // Трёхзначные флаги: у корня True, у корзины null (как в файле).
    let root = root_group(&xml);
    assert_text(root, "EnableAutoType", "True", "Group Root");
    assert_text(root, "EnableSearching", "True", "Group Root");
    assert_text(
        root,
        "DefaultAutoTypeSequence",
        "{USERNAME}{TAB}{PASSWORD}",
        "Group Root",
    );
    let bin = xml.find_by_uuid("Group", RECYCLE_BIN).unwrap();
    for tag in ["EnableAutoType", "EnableSearching"] {
        let value = bin.text_of(tag).unwrap_or("null");
        assert_eq!(value, "null", "Group Recycle Bin: <{}> изменён", tag);
    }

    // IsExpanded в файле нет — у KeePass по умолчанию True, писать False нельзя.
    let templates = xml.find_by_uuid("Group", TEMPLATES).unwrap();
    assert_ne!(
        templates.text_of("IsExpanded"),
        Some("False"),
        "Group Templates: отсутствующий <IsExpanded> записан как False"
    );
}

fn assert_entry_fields(entry: &Node, what: &str) {
    for (tag, expected) in [
        ("OverrideURL", "cmd://firefox {URL}"),
        ("ForegroundColor", "#112233"),
        ("BackgroundColor", "#445566"),
        ("QualityCheck", "False"),
        ("PreviousParentGroup", TEMPLATES),
        // уже сохранялись до Step 17
        ("Tags", "alpha;beta"),
        ("IconID", "12"),
    ] {
        assert_text(entry, tag, expected, what);
    }
    let auto_type = entry.child("AutoType").unwrap();
    assert_text(auto_type, "DataTransferObfuscation", "1", what);
    assert_text(auto_type, "DefaultSequence", "{PASSWORD}{ENTER}", what);
}

#[test]
fn entry_fields_survive_save() {
    let xml = saved_xml();
    let entry = xml.find_by_uuid("Entry", ENTRY).expect("запись потеряна");
    assert_entry_fields(entry, "Entry");

    let history = entry
        .child("History")
        .and_then(|h| h.child("Entry"))
        .expect("история записи потеряна");
    assert_entry_fields(history, "Entry/History");
}

fn assert_unknown(owner: &Node, what: &str, with_secret: bool) {
    let unknown = owner
        .child(UNKNOWN_TAG)
        .unwrap_or_else(|| panic!("{}: неизвестный элемент <{}> потерян", what, UNKNOWN_TAG));
    assert_eq!(
        unknown.attr("Origin"),
        Some("fixture"),
        "{}: атрибут потерян",
        what
    );
    assert_text(unknown, "Inner", "unknown-value", what);
    if with_secret {
        let secret = unknown.child("Value").expect("protected-значение потеряно");
        assert_eq!(
            secret.text, "unknown-secret",
            "{}: protected-значение испорчено",
            what
        );
        assert_eq!(
            secret.attr("Protected"),
            Some("True"),
            "{}: флаг Protected потерян",
            what
        );
    }
}

#[test]
fn unknown_elements_survive_save() {
    let xml = saved_xml();
    assert_unknown(xml.child("Meta").unwrap(), "Meta", false);
    assert_unknown(
        xml.find_by_uuid("Group", WORK).unwrap(),
        "Group Work",
        false,
    );

    let entry = xml.find_by_uuid("Entry", ENTRY).unwrap();
    assert_unknown(entry, "Entry", true);
    let history = entry.child("History").unwrap().child("Entry").unwrap();
    assert_unknown(history, "Entry/History", true);
}

/// Protected-значения расшифровываются одним потоком по порядку документа. Protected
/// внутри неизвестного элемента, пропущенный без расшифровки, сдвигал поток — и все
/// следующие пароли молча превращались в мусор (найдено в Step 17 п.2).
#[test]
fn protected_values_after_unknown_element_are_intact() {
    common::init();
    let source = temp_path(FIXTURE);
    std::fs::copy(resource(FIXTURE), &source).unwrap();
    open(&source);
    let read = export_xml(&source);
    close(&source);

    let saved = saved_xml();
    for (xml, stage) in [(&read, "после чтения"), (&saved, "после сохранения")]
    {
        let entry = xml.find_by_uuid("Entry", ENTRY).unwrap();
        let history = entry.child("History").unwrap().child("Entry").unwrap();
        for (node, key, expected) in [
            (entry, "Password", "af-pass-2"),
            (entry, "Custom Secret", "secret-value"),
            (history, "Password", "af-pass-1"),
            (history, "Custom Secret", "secret-value"),
        ] {
            let value = node.string_field(key).map(|v| v.text.as_str());
            assert_eq!(
                value,
                Some(expected),
                "[{}] protected-поле {} испорчено",
                stage,
                key
            );
        }
    }
}
