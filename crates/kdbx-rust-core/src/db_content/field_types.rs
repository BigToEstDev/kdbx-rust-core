// The types of the fields of an entry our app gives them (a phone, ...) - not a kdbx notion: they are kept
// in the CustomData of the entry under one key of ours, a JSON object, field name -> type (pass-docs,
// Step 76). The core does not read the types: one it does not know - written by a newer client - travels
// as the string it is. A text field is not written; no typed field - no key.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::constants::custom_data_key::PASSHOLDER_FIELD_TYPES;
use crate::db_content::{CustomData, Item};
use crate::util;

// Field name -> type. Sorted: the same types make the same JSON
pub(crate) type FieldTypes = BTreeMap<String, String>;

// The types kept in the entry. A value that is no JSON object, a type that is no string or is empty - no
// error: those fields are text
pub(crate) fn read(custom_data: &CustomData) -> FieldTypes {
    let Some(value) = custom_data.get_item_value(PASSHOLDER_FIELD_TYPES) else {
        return FieldTypes::new();
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(value) else {
        return FieldTypes::new();
    };
    map.into_iter()
        .filter_map(|(name, field_type)| match field_type {
            Value::String(s) if !s.is_empty() => Some((name, s)),
            _ => None,
        })
        .collect()
}

// Puts the types in the entry. The same types as kept leave the item as it is, its modification time
// too; no types remove it. Any other key of the CustomData is not touched
pub(crate) fn write(custom_data: &mut CustomData, types: &FieldTypes) {
    if types.is_empty() {
        custom_data.remove_item(PASSHOLDER_FIELD_TYPES);
        return;
    }
    if custom_data.get_item_value(PASSHOLDER_FIELD_TYPES).is_some() && read(custom_data) == *types {
        return;
    }
    // A map of strings always serializes
    let value = serde_json::to_string(types).unwrap_or_default();
    custom_data.insert_item(Item::from_kv_with_modification_time(
        PASSHOLDER_FIELD_TYPES,
        &value,
        util::now_utc(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_value(value: &str) -> CustomData {
        let mut data = CustomData::default();
        data.insert_item(Item::from_kv(PASSHOLDER_FIELD_TYPES, value));
        data
    }

    fn types(pairs: &[(&str, &str)]) -> FieldTypes {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn reads_the_types_kept() {
        let data = with_value(r#"{"PIN":"phone","Card":"card"}"#);
        assert_eq!(read(&data), types(&[("PIN", "phone"), ("Card", "card")]));
    }

    #[test]
    fn no_key_or_a_broken_value_reads_as_no_types() {
        assert!(read(&CustomData::default()).is_empty());
        assert!(read(&with_value("not json")).is_empty());
        assert!(read(&with_value(r#"["PIN"]"#)).is_empty());
    }

    #[test]
    fn a_type_that_is_no_string_or_empty_is_left_out() {
        let data = with_value(r#"{"PIN":"phone","A":1,"B":"","C":null}"#);
        assert_eq!(read(&data), types(&[("PIN", "phone")]));
    }

    #[test]
    fn writes_the_types_as_json_with_a_modification_time() {
        let mut data = CustomData::default();
        write(&mut data, &types(&[("PIN", "phone")]));

        let item = data.get_item(PASSHOLDER_FIELD_TYPES).unwrap();
        assert_eq!(item.value, r#"{"PIN":"phone"}"#);
        assert!(item.last_modification_time.is_some());
    }

    #[test]
    fn no_types_remove_the_key() {
        let mut data = with_value(r#"{"PIN":"phone"}"#);
        write(&mut data, &FieldTypes::new());
        assert!(data.get_item(PASSHOLDER_FIELD_TYPES).is_none());
    }

    #[test]
    fn the_same_types_leave_the_item_as_read() {
        // Spaces as another client may write them, and no modification time
        let mut data = with_value(r#"{ "PIN" : "phone" }"#);
        let before = data.clone();
        write(&mut data, &types(&[("PIN", "phone")]));
        assert_eq!(data, before);
    }

    #[test]
    fn other_keys_are_not_touched() {
        let mut data = with_value(r#"{"PIN":"phone"}"#);
        data.insert_item(Item::from_kv("KPXC_X", "foreign"));

        write(&mut data, &types(&[("PIN", "card")]));
        assert_eq!(data.get_item_value("KPXC_X"), Some("foreign"));

        write(&mut data, &FieldTypes::new());
        assert_eq!(data.get_item_value("KPXC_X"), Some("foreign"));
    }
}
