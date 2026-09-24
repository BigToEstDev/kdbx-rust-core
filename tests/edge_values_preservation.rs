//! Граничные значения полей переживают сохранение (Step 19, п.6).
//!
//! Step 17 проверял, что каждый элемент KDBX 4.1 на месте, но не то, **чем** он заполнен.
//! Ломаются парсеры обычно как раз на содержимом: юникод вне BMP, переносы строк в стиле
//! Windows, пустые и пробельные значения, очень длинные строки, спецсимволы XML в ключах
//! полей, пустые и общие вложения.
//!
//! Фикстура `edge_values_41.kdbx` собрана сторонней реализацией (pykeepass,
//! `tools/kdbx-oracle/gen_fixtures.py`, `build_edge_fixture`); значения продублированы здесь
//! константами — менять вместе. Полное сравнение до / после — `compare_roundtrip.py`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use common::xml::{parse_xml, Node};
use onekeepass_core::db_service;

const PASSWORD: &str = "test-pass-1234";
const FIXTURE: &str = "edge_values_41.kdbx";

// UUID объектов фикстуры (EDGE_UUIDS в генераторе) в виде, как они лежат в XML — base64.
const GROUP: &str = "PHqeEAAAQACAAAAAAAAAAQ==";
const ENTRY: &str = "PHqeEAAAQACAAAAAAAAAEA==";
const ENTRY2: &str = "PHqeEAAAQACAAAAAAAAAEQ==";

// EDGE_* в генераторе.
const UNICODE: &str =
    "спам \u{1F510}\u{1F1FA}\u{1F1E6} e\u{301} \u{200b} \u{202e}RTL\u{202c} 中文 \u{1D54F}";
const MULTILINE: &str = "первая строка\nвторая строка\r\nтретья\tс табом\n\nпустая выше";
const SPACES: &str = "   ";
const XML_CHARS: &str = "a & b < c > d \" e";
const KEY_WITH_XML: &str = "Ключ & <со> \"спецсимволами\"";
const LONG_PIECE: &str = "длинная-";
const LONG_REPEATS: usize = 12000;

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
        "okp_edge_{}_{}_{}",
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

/// XML базы после цикла «открыть чужой файл → сохранить → открыть сохранённое».
fn saved_xml() -> Node {
    saved_xml_with_text().0
}

/// То же самое плюс сам текст XML: часть проверок смотрит на разметку, а не на значения
/// (наш ридер, в отличие от KeePass и pykeepass, не нормализует переводы строк, поэтому
/// потерю возврата каретки видно только в разметке).
fn saved_xml_with_text() -> (Node, String) {
    common::init();
    let source = temp_path(FIXTURE);
    std::fs::copy(resource(FIXTURE), &source).unwrap();
    open(&source);

    let saved = temp_path("saved.kdbx");
    db_service::save_to_db_file(&source, &saved).expect("сохранение в новый файл не удалось");
    close(&source);

    open(&saved);
    let xml_path = temp_path("dump.xml");
    db_service::export_as_xml(&saved, &xml_path).expect("выгрузка XML не удалась");
    let xml = std::fs::read_to_string(&xml_path).unwrap();
    let _ = std::fs::remove_file(&xml_path);
    close(&saved);
    (parse_xml(&xml), xml)
}

fn entry(xml: &Node) -> &Node {
    xml.find_by_uuid("Entry", ENTRY).expect("запись потеряна")
}

fn field(entry: &Node, key: &str) -> String {
    entry
        .string_field(key)
        .unwrap_or_else(|| panic!("поле {:?} потеряно", key))
        .text
        .clone()
}

#[test]
fn unicode_survives_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    assert_eq!(
        field(entry, "Title"),
        UNICODE,
        "заголовок с юникодом изменён"
    );
    assert_eq!(
        field(entry, "UserName"),
        format!("user {}", UNICODE),
        "имя пользователя с юникодом изменено"
    );
    assert_eq!(
        entry.text_of("Tags"),
        Some("тег-один;тег & два;\u{1F510}"),
        "теги с юникодом и амперсандом изменены"
    );

    let group = xml.find_by_uuid("Group", GROUP).expect("группа потеряна");
    assert_eq!(
        group.text_of("Name"),
        Some("Группа & <граничная> \u{1F510}"),
        "имя группы изменено"
    );
}

/// Перенос строки в стиле Windows: XML нормализует "\r\n" в "\n" при чтении, поэтому "\r"
/// переживает сохранение, только если записан как &#13;. До Step 19 он терялся при каждом
/// сохранении.
#[test]
fn windows_line_endings_survive_save() {
    let (xml, xml_text) = saved_xml_with_text();

    // Главная проверка — разметка: "" должен быть записан ссылкой, иначе KeePass,
    // KeePassXC и pykeepass прочитают заметку уже без него
    assert!(
        xml_text.contains("&#13;"),
        "возврат каретки записан как есть, а не как &#13; — при чтении он пропадёт"
    );

    assert_eq!(field(entry(&xml), "Notes"), MULTILINE, "заметка записи");

    let group = xml.find_by_uuid("Group", GROUP).unwrap();
    assert_eq!(
        group.text_of("Notes"),
        Some(MULTILINE),
        "заметка группы: потерян возврат каретки"
    );

    // В истории — та же заметка
    let history_entry = entry(&xml)
        .at(&["History", "Entry"])
        .expect("версия в истории потеряна");
    assert_eq!(
        field(history_entry, "Notes"),
        MULTILINE,
        "заметка в истории"
    );
}

#[test]
fn empty_blank_and_long_values_survive_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    assert_eq!(field(entry, "Пустое"), "", "пустое значение");
    assert_eq!(
        field(entry, "Пробелы"),
        SPACES,
        "значение из одних пробелов"
    );
    assert_eq!(
        field(entry, "Длинное").len(),
        LONG_PIECE.len() * LONG_REPEATS,
        "длинное значение обрезано"
    );
    // Пустое protected-значение: поток шифрования не должен на нём спотыкаться
    assert_eq!(field(entry, "Пустой секрет"), "", "пустой секрет");
    assert_eq!(
        field(entry, "Секрет"),
        "значение \u{1F510}",
        "непустой секрет после пустого — сдвиг inner stream"
    );
}

#[test]
fn xml_special_characters_in_keys_and_values_survive_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    assert_eq!(
        field(entry, KEY_WITH_XML),
        XML_CHARS,
        "значение поля, у которого спецсимволы XML в ключе"
    );
    assert_eq!(
        field(entry, "URL"),
        "https://example.com/?a=1&b=2",
        "URL с амперсандом"
    );
    assert_eq!(
        field(entry, "Password"),
        "пароль-2 \u{1F510}",
        "пароль со спецсимволами"
    );
}

/// Одно и то же вложение у двух записей и пустое вложение: при перепаковке во внутренний
/// заголовок ссылки не должны перепутаться или потеряться.
#[test]
fn shared_and_empty_attachments_survive_save() {
    let xml = saved_xml();
    let entry = entry(&xml);

    let names: Vec<&str> = entry
        .children
        .iter()
        .filter(|c| c.tag == "Binary")
        .filter_map(|c| c.text_of("Key"))
        .collect();
    assert_eq!(
        names,
        vec!["общий.txt", "пустой.bin"],
        "вложения записи потеряны"
    );

    let second = xml
        .find_by_uuid("Entry", ENTRY2)
        .expect("вторая запись потеряна");
    let second_names: Vec<&str> = second
        .children
        .iter()
        .filter(|c| c.tag == "Binary")
        .filter_map(|c| c.text_of("Key"))
        .collect();
    assert_eq!(
        second_names,
        vec!["общий.txt"],
        "общее вложение второй записи потеряно"
    );
}

/// CustomData записи, как её пишет KeePassXC для интеграции с браузером.
#[test]
fn keepassxc_custom_data_survives_save() {
    let xml = saved_xml();
    let custom_data = entry(&xml)
        .child("CustomData")
        .expect("CustomData записи потеряна");

    for (key, value) in [
        ("KPXC_BROWSER_example.com", "true"),
        ("_LAST_MODIFIED", "Sun Jan 12 03:51:58 2020 GMT"),
    ] {
        let item = custom_data
            .child_with("Item", "Key", key)
            .unwrap_or_else(|| panic!("CustomData: элемент {:?} потерян", key));
        assert_eq!(item.text_of("Value"), Some(value), "CustomData: {:?}", key);
    }
}
