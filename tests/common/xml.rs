//! Минимальное XML-дерево для тестов сохранности данных.
//!
//! Тесты выгружают базу через `db_service::export_as_xml` (protected-значения там
//! открытым текстом) и проверяют элементы по месту в дереве. Полноценный XML-разбор
//! для этого не нужен — хватает тега, атрибутов, текста и детей.
//!
//! Используется из `tests/all_fields_preservation.rs` (Step 17) и
//! `tests/unknown_elements_preservation.rs` (Step 18).

// Каждый тестовый бинарь берёт из модуля своё подмножество.
#![allow(dead_code)]

use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, Default)]
pub struct Node {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn child(&self, tag: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.tag == tag)
    }

    pub fn text_of(&self, tag: &str) -> Option<&str> {
        self.child(tag).map(|c| c.text.as_str())
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Спуск по цепочке тегов: `at(&["Meta", "MemoryProtection"])`.
    pub fn at(&self, path: &[&str]) -> Option<&Node> {
        path.iter().try_fold(self, |node, tag| node.child(tag))
    }

    /// Первый (в порядке документа) объект `tag` с `<UUID>` = `uuid`. Основная запись
    /// идёт раньше своей истории, поэтому для записи это всегда текущая версия.
    pub fn find_by_uuid(&self, tag: &str, uuid: &str) -> Option<&Node> {
        if self.tag == tag && self.text_of("UUID") == Some(uuid) {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find_by_uuid(tag, uuid))
    }

    /// Ребёнок `tag`, у которого дочерний `key_tag` равен `key`
    /// (`<Item><Key>X</Key>…`, `<Icon><UUID>…`).
    pub fn child_with(&self, tag: &str, key_tag: &str, key: &str) -> Option<&Node> {
        self.children
            .iter()
            .filter(|c| c.tag == tag)
            .find(|c| c.text_of(key_tag) == Some(key))
    }

    /// Поле записи `<String><Key>key</Key><Value>…</Value></String>` целиком.
    pub fn string_entry(&self, key: &str) -> Option<&Node> {
        self.children
            .iter()
            .filter(|c| c.tag == "String")
            .find(|c| c.text_of("Key") == Some(key))
    }

    /// Значение строкового поля записи.
    pub fn string_field(&self, key: &str) -> Option<&Node> {
        self.string_entry(key).and_then(|c| c.child("Value"))
    }
}

pub fn parse_xml(xml: &str) -> Node {
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
                let value = String::from_utf8(a.value.to_vec()).unwrap();
                (
                    String::from_utf8(a.key.as_ref().to_vec()).unwrap(),
                    // В XML значение атрибута экранировано: сравниваем с исходным текстом
                    quick_xml::escape::unescape(&value).unwrap().into_owned(),
                )
            })
            .collect(),
        ..Default::default()
    }
}
