//! Неизвестные элементы переживают сохранение на любом уровне дерева (Step 18).
//!
//! До Step 18 ядро хранило незнакомый тег только у Meta / Group / Entry
//! (`XmlReader::keep_unknown`). Всё, что лежало глубже — внутри `Times`, `AutoType`,
//! `CustomData/Item`, `MemoryProtection`, `CustomIcons`, `DeletedObject`, на уровне
//! `Root` / `KeePassFile` — читалось и молча выбрасывалось: пересохранение чужой базы
//! теряло данные, которых мы не показываем.
//!
//! Фикстура `unknown_everywhere_41.kdbx` собрана сторонней реализацией (pykeepass,
//! `tools/kdbx-oracle/gen_fixtures.py`, `build_unknown_fixture`): незнакомый тег стоит
//! на каждом уровне сразу, свой на каждом месте — по имени видно, какой уровень потерян.
//! Имена и значения продублированы здесь константами — менять вместе с генератором.
//! Полное сравнение до / после — `tools/kdbx-oracle/compare_roundtrip.py`.
//!
//! Сценарий: открыть фикстуру → сохранить в новый файл → открыть его → выгрузить XML
//! (`export_as_xml`, protected-значения там открытым текстом) → проверить элементы.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use common::xml::{parse_xml, Node};
use kdbx_rust_core::db_service;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "unknown_everywhere_41.kdbx";

// UUID объектов фикстуры (UNK_UUIDS в генераторе) в виде, как они лежат в XML — base64.
const GROUP: &str = "ex5cYAAAQACAAAAAAAAAAQ==";
const ENTRY: &str = "ex5cYAAAQACAAAAAAAAAEA==";

// Атрибут и вложенность неизвестных элементов (UNK_ATTR, UNK_NESTED_* в генераторе).
const UNK_ATTR_NAME: &str = "Origin";
const UNK_ATTR_VALUE: &str = "step-18 & <fixture>";
const UNK_NESTED_TEXT: &str = "deep & nested";

// Protected-значения внутри неизвестных элементов (UNK_SECRET_* в генераторе).
const SECRET_IN_TIMES: &str = "secret-in-times";
const SECRET_IN_CUSTOM_DATA: &str = "secret-in-custom-data";

static SEQ: AtomicU64 = AtomicU64::new(0);

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
        "okp_unknown_{}_{}_{}",
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

// --- проверки -----------------------------------------------------------------------

/// Неизвестный элемент на своём месте: тег, атрибут и текстовый лист внутри.
fn assert_unknown<'a>(parent: &'a Node, tag: &str, where_: &str) -> &'a Node {
    let element = parent
        .child(tag)
        .unwrap_or_else(|| panic!("{}: <{}> потерян при сохранении", where_, tag));
    assert_eq!(
        element.attr(UNK_ATTR_NAME),
        Some(UNK_ATTR_VALUE),
        "{}: атрибут @{} потерян или изменён",
        where_,
        UNK_ATTR_NAME
    );
    assert_eq!(
        element.text_of("Inner"),
        Some(format!("value for {}", where_).as_str()),
        "{}: содержимое <Inner> потеряно или изменено",
        where_
    );
    element
}

fn at<'a>(xml: &'a Node, path: &[&str], what: &str) -> &'a Node {
    xml.at(path)
        .unwrap_or_else(|| panic!("{}: путь {:?} не найден", what, path))
}

fn group(xml: &Node) -> &Node {
    xml.find_by_uuid("Group", GROUP).expect("группа потеряна")
}

fn entry(xml: &Node) -> &Node {
    xml.find_by_uuid("Entry", ENTRY).expect("запись потеряна")
}

// --- тесты --------------------------------------------------------------------------

/// Уровни выше объектов: сам файл, Root и DeletedObjects — у них до Step 18 не было
/// места для хранения, поэтому терялось всё.
#[test]
fn unknown_elements_above_objects_survive_save() {
    let xml = saved_xml();

    assert_unknown(&xml, "XFileUnknown", "file");

    let root = at(&xml, &["Root"], "Root");
    assert_unknown(root, "XRootUnknown", "root");

    let deleted = at(&xml, &["Root", "DeletedObjects"], "Root/DeletedObjects");
    assert_unknown(deleted, "XDeletedObjectsUnknown", "deleted_objects");
    let object = deleted
        .child("DeletedObject")
        .expect("Root/DeletedObjects: <DeletedObject> потерян");
    assert_unknown(object, "XDeletedObjectUnknown", "deleted_object");
}

/// Meta и всё, что внутри неё: MemoryProtection, иконки, CustomData.
#[test]
fn unknown_elements_in_meta_survive_save() {
    let xml = saved_xml();
    let meta = at(&xml, &["Meta"], "Meta");

    // Хранилось и до Step 18 — страховка от регрессии.
    assert_unknown(meta, "XMetaUnknown", "meta");

    let protection = at(&xml, &["Meta", "MemoryProtection"], "Meta/MemoryProtection");
    assert_unknown(protection, "XProtectUnknown", "memory_protection");

    let icons = at(&xml, &["Meta", "CustomIcons"], "Meta/CustomIcons");
    assert_unknown(icons, "XIconsUnknown", "custom_icons");
    let icon = icons
        .child("Icon")
        .expect("Meta/CustomIcons: <Icon> потерян");
    assert_unknown(icon, "XIconUnknown", "icon");

    // Шаблон pykeepass добавляет в Meta свои Item (KPXC_*) — ищем наш по ключу
    let item = at(&xml, &["Meta", "CustomData"], "Meta/CustomData")
        .child_with("Item", "Key", "X-Meta-Key")
        .expect("Meta/CustomData: <Item> с ключом X-Meta-Key потерян");
    assert_unknown(item, "XMetaItemUnknown", "meta_item");
}

/// Группа: сама (хранилось и раньше), её Times и её CustomData/Item.
#[test]
fn unknown_elements_in_group_survive_save() {
    let xml = saved_xml();
    let group = group(&xml);

    assert_unknown(group, "XGroupUnknown", "group");
    assert_unknown(
        at(group, &["Times"], "Group/Times"),
        "XGroupTimesUnknown",
        "group_times",
    );
    let item = at(group, &["CustomData"], "Group/CustomData")
        .child_with("Item", "Key", "X-Group-Key")
        .expect("Group/CustomData: <Item> с ключом X-Group-Key потерян");
    assert_unknown(item, "XGroupItemUnknown", "group_item");
}

/// Запись: Times, AutoType с Association, String, Binary, CustomData/Item и сама запись
/// с вложенным тегом в теге.
#[test]
fn unknown_elements_in_entry_survive_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    let unknown = assert_unknown(entry, "XEntryUnknown", "entry");
    let deep = unknown
        .at(&["Level1", "Level2", "Level3"])
        .expect("entry: вложенные Level1/Level2/Level3 потеряны");
    assert_eq!(
        deep.text, UNK_NESTED_TEXT,
        "entry: текст вложенного элемента потерян или изменён"
    );

    assert_unknown(
        at(entry, &["Times"], "Entry/Times"),
        "XEntryTimesUnknown",
        "entry_times",
    );

    let auto_type = at(entry, &["AutoType"], "Entry/AutoType");
    assert_unknown(auto_type, "XAutoTypeUnknown", "auto_type");
    assert_unknown(
        at(auto_type, &["Association"], "Entry/AutoType/Association"),
        "XAssociationUnknown",
        "association",
    );

    let title = entry
        .string_entry("Title")
        .expect("Entry: <String> с Key=Title потерян");
    assert_unknown(title, "XStringUnknown", "string");

    let binary = entry.child("Binary").expect("Entry: <Binary> потерян");
    assert_unknown(binary, "XBinaryUnknown", "binary");

    let item = at(entry, &["CustomData"], "Entry/CustomData")
        .child_with("Item", "Key", "X-Entry-Key")
        .expect("Entry/CustomData: <Item> с ключом X-Entry-Key потерян");
    assert_unknown(item, "XEntryItemUnknown", "entry_item");
}

/// Версия в истории — такая же запись: её собственные неизвестные элементы тоже
/// должны пережить сохранение.
#[test]
fn unknown_elements_in_history_survive_save() {
    let xml = saved_xml();
    let history_entry = at(entry(&xml), &["History", "Entry"], "Entry/History/Entry");

    assert_unknown(history_entry, "XHistoryEntryUnknown", "history_entry");
    assert_unknown(
        at(history_entry, &["Times"], "History/Entry/Times"),
        "XHistoryTimesUnknown",
        "history_times",
    );
}

/// Protected-значение внутри неизвестного элемента: inner stream идёт по порядку
/// документа, поэтому такое значение нужно вернуть на то же место. Два секрета стоят
/// по разные стороны от полей записи — сдвиг потока в любую сторону портит пароли.
#[test]
fn protected_values_inside_unknown_elements_survive_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    let in_times = at(entry, &["Times", "XEntryTimesUnknown"], "Entry/Times");
    assert_eq!(
        in_times.text_of("Value"),
        Some(SECRET_IN_TIMES),
        "protected-значение внутри Times потеряно или расшифровано мусором"
    );

    let in_custom_data = at(entry, &["CustomData"], "Entry/CustomData")
        .child_with("Item", "Key", "X-Entry-Key")
        .expect("Entry/CustomData: <Item> с ключом X-Entry-Key потерян")
        .child("XEntryItemUnknown")
        .expect("Entry/CustomData/Item: <XEntryItemUnknown> потерян");
    assert_eq!(
        in_custom_data.text_of("Value"),
        Some(SECRET_IN_CUSTOM_DATA),
        "protected-значение внутри CustomData потеряно или расшифровано мусором"
    );

    // Пароли самой записи и версии истории — контроль, что поток не сдвинулся.
    assert_eq!(
        entry.string_field("Password").map(|n| n.text.as_str()),
        Some("unk-pass-2"),
        "пароль записи испорчен — сдвиг inner stream"
    );
    let history_entry = at(entry, &["History", "Entry"], "Entry/History/Entry");
    assert_eq!(
        history_entry
            .string_field("Password")
            .map(|n| n.text.as_str()),
        Some("unk-pass-1"),
        "пароль версии в истории испорчен — сдвиг inner stream"
    );
}
