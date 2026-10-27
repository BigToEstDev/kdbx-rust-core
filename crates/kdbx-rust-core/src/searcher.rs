//! The term search behind `search_term`: an entry is found by what its card shows - the title and the
//! user name - and never by a protected field.
//!
//! The term is plain text, not a pattern: what the user types is looked for as it is, case aside.

use crate::constants::entry_keyvalue_key::{TITLE, USER_NAME};
use crate::db_content::Entry;
use crate::form_data::EntrySummary;

/// The term as it is matched - trimmed and lower-cased; None when nothing is left to look for.
pub(crate) fn normalized_term(term: &str) -> Option<String> {
    let term = term.trim();
    (!term.is_empty()).then(|| term.to_lowercase())
}

/// Whether the entry is found by `term`, taken from [normalized_term].
///
/// The values matched are those of `summary` - place holders resolved, as the card shows them; whether a
/// field may be matched at all is the entry's: a field marked protected is never looked into, whatever
/// its key.
pub(crate) fn matches(term: &str, entry: &Entry, summary: &EntrySummary) -> bool {
    let open = |key: &str| {
        entry
            .entry_field
            .find_key_value(key)
            .is_some_and(|kv| !kv.protected)
    };
    let holds = |value: &Option<String>| {
        value
            .as_deref()
            .is_some_and(|v| v.to_lowercase().contains(term))
    };

    (open(TITLE) && holds(&summary.title)) || (open(USER_NAME) && holds(&summary.secondary_title))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_content::{BinaryKeyValue, KeyValue};

    fn entry(fields: &[(&str, &str, bool)]) -> Entry {
        let mut e = Entry::new();
        e.tags = "Banks;Finance".into();
        for (key, value, protected) in fields {
            e.entry_field.insert_key_value(KeyValue {
                key: (*key).into(),
                value: (*value).into(),
                protected: *protected,
            });
        }
        e
    }

    fn summary_of(e: &Entry) -> EntrySummary {
        EntrySummary {
            title: e.find_kv_field_value(TITLE),
            secondary_title: e.find_kv_field_value(USER_NAME),
            ..Default::default()
        }
    }

    fn found(term: &str, e: &Entry) -> bool {
        let summary = summary_of(e);
        normalized_term(term).is_some_and(|t| matches(&t, e, &summary))
    }

    fn bank() -> Entry {
        let mut e = entry(&[
            ("Title", "MyBank", false),
            ("UserName", "Alice", false),
            ("Password", "Secr3t!", true),
            ("URL", "https://mybank.com", false),
            ("Notes", "branch on main street", false),
            ("PIN", "4321", false),
        ]);
        e.binary_key_values.push(BinaryKeyValue {
            key: "resume.pdf".into(),
            value: String::default(),
            index_ref: 0,
            data_hash: 0,
            data_size: 0,
        });
        e
    }

    #[test]
    fn the_title_is_matched_by_a_part_of_it_whatever_the_case() {
        let e = bank();
        assert!(found("bank", &e));
        assert!(found("MYBANK", &e));
        assert!(found("yBa", &e));
    }

    #[test]
    fn the_user_name_is_matched_too() {
        assert!(found("alice", &bank()));
    }

    #[test]
    fn letters_beyond_ascii_are_matched_whatever_the_case() {
        let e = entry(&[
            ("Title", "Почта Яндекса", false),
            ("UserName", "Ärger", false),
        ]);
        assert!(found("ПОЧТА", &e));
        assert!(found("яндекс", &e));
        assert!(found("ärg", &e));
    }

    #[test]
    fn the_password_is_never_looked_into() {
        assert!(!found("Secr3t", &bank()));
    }

    #[test]
    fn other_fields_tags_and_attachments_are_not_looked_into() {
        let e = bank();
        assert!(!found("mybank.com", &e));
        assert!(!found("street", &e));
        assert!(!found("4321", &e));
        assert!(!found("Finance", &e));
        assert!(!found("resume", &e));
    }

    #[test]
    fn a_protected_title_or_user_name_is_not_looked_into() {
        let e = entry(&[("Title", "Hidden", true), ("UserName", "bob", true)]);
        assert!(!found("hidden", &e));
        assert!(!found("bob", &e));
    }

    #[test]
    fn the_term_is_text_and_not_a_pattern() {
        let e = entry(&[
            ("Title", "c++ (work) [old]", false),
            ("UserName", "a.b", false),
        ]);
        assert!(found("c++", &e));
        assert!(found("(work)", &e));
        assert!(found("[old", &e));
        assert!(found("a.b", &e));
        // What used to be a broken pattern is a term that is simply not there
        assert!(!found("user\\", &e));
        // A dot is a dot, not "any character"
        assert!(!found(".", &bank()));
    }

    #[test]
    fn a_blank_term_finds_nothing() {
        assert_eq!(normalized_term(""), None);
        assert_eq!(normalized_term("   "), None);
        assert!(!found(" ", &bank()));
    }

    #[test]
    fn spaces_around_the_term_are_not_part_of_it() {
        assert_eq!(normalized_term("  Bank "), Some("bank".to_string()));
        assert!(found(" bank ", &bank()));
    }

    #[test]
    fn an_entry_without_title_and_user_name_is_not_found() {
        let e = entry(&[("Password", "x", true)]);
        assert!(!found("x", &e));
    }
}
