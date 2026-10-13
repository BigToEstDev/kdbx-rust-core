//! Поля формы записи в тестах (Step 45): форма — один список `fields`, все строки записи по порядку,
//! `Title` и `Notes` тоже там. Тесты правят форму через её JSON.

// Каждый тестовый бинарь берёт из модуля своё подмножество.
#![allow(dead_code)]

use serde_json::{json, Value};

/// Значение поля формы по ключу (первое с этим ключом).
pub fn field<'a>(form: &'a Value, key: &str) -> Option<&'a str> {
    form["fields"]
        .as_array()?
        .iter()
        .find(|f| f["key"] == key)
        .and_then(|f| f["value"].as_str())
}

/// Ставит значение поля формы; поля нет — добавляет его в конец, незащищённым текстом.
pub fn set_field(form: &mut Value, key: &str, value: &str) {
    let fields = form["fields"].as_array_mut().expect("fields в форме");
    match fields.iter_mut().find(|f| f["key"] == key) {
        Some(f) => f["value"] = json!(value),
        None => fields.push(json!({
            "key": key,
            "value": value,
            "protected": false,
            "data_type": "Text",
            "current_opt_token": null,
        })),
    }
}

/// Делает поле формы защищённым (protected в файле).
pub fn protect(form: &mut Value, key: &str) {
    let fields = form["fields"].as_array_mut().expect("fields в форме");
    let f = fields
        .iter_mut()
        .find(|f| f["key"] == key)
        .expect("поле в форме");
    f["protected"] = json!(true);
}

/// Ключи полей формы по порядку.
pub fn keys(form: &Value) -> Vec<String> {
    form["fields"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| f["key"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}
