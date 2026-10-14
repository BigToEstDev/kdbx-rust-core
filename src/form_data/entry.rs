use chrono::NaiveDateTime;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::From;
use uuid::Uuid;

use crate::constants::entry_keyvalue_key::*;
use crate::password_generator::PasswordScore;

use crate::error::{Error, Result};

use crate::db_content::{
    join_tags, split_tags, AutoType, BinaryKeyValue, Entry, EntryField, FieldDataType, KeepassFile,
    KeyValue, OtpData, Root,
};

pub use crate::db_content::CurrentOtpTokenData;

// #[derive(Debug, Clone, Serialize)]
// One field of an entry as the form shows it
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct KeyValueData {
    key: String,
    value: Option<String>,
    protected: bool,
    // Text unless the value is a one-time password the core can generate tokens from
    data_type: FieldDataType,

    // Only relevant for PASSWORD field and in other cases it is None
    // We get the PasswordScore based on the String value of password
    // Only serialization is enabled so as to send the data to UI
    #[serde(skip_deserializing)]
    pub password_score: Option<PasswordScore>,

    // Following are set on otp token generation
    // Should this also use 'skip_deserializing' ?
    pub current_opt_token: Option<CurrentOtpTokenData>,
}

// Written by hand: the derived one would print the secret - see crate::redacted
impl std::fmt::Debug for KeyValueData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyValueData")
            .field("key", &self.key)
            .field("value", &crate::redacted::redacted_opt(&self.value))
            .field("protected", &self.protected)
            .field("data_type", &self.data_type)
            .field("current_opt_token", &self.current_opt_token)
            .finish_non_exhaustive()
    }
}

impl From<&KeyValue> for KeyValueData {
    fn from(kv: &KeyValue) -> Self {
        let password_score = if kv.key == PASSWORD {
            Some((&kv.value).into())
        } else {
            None
        };
        Self {
            key: kv.key.clone(),
            value: Some(kv.value.clone()),
            protected: kv.protected,
            data_type: FieldDataType::default(),
            password_score,
            current_opt_token: None,
        }
    }
}

impl From<&KeyValueData> for KeyValue {
    fn from(kvd: &KeyValueData) -> Self {
        let mut kv = KeyValue::new();
        kv.key = kvd.key.clone();
        kv.value = kvd
            .value
            .as_ref()
            .map_or_else(String::default, |v| v.clone());
        kv.protected = kvd.protected;
        kv
    }
}

impl KeyValueData {
    // Called to generate an otp token if there is a parsed otp data available for this KV
    // The data type will be overriden to be 'OneTimePassword'
    //
    // An entry from the original KeePass keeps its totp in the custom fields TimeOtp-*
    // (db_content/time_otp.rs) and a field may also hold an otpauth url, ours or created in another
    // app. Both are recognised while reading the entry, so a parsed value here means this field is a
    // one-time password field
    fn generate_otp_on_check(&mut self, parsed_otp_values: &Option<HashMap<String, OtpData>>) {
        if let Some(parsed_otp_data) = parsed_otp_values.as_ref().and_then(|m| m.get(&self.key)) {
            self.data_type = FieldDataType::OneTimePassword;
            match parsed_otp_data.current_otp_token_data() {
                Ok(token_data) => {
                    self.current_opt_token = Some(token_data);
                }
                Err(e) => {
                    info!("Generating current otp failed {}", e);
                }
            }
        }
    }
}

use super::{categories, parsing};

// The form of an entry: every string of the entry - Title and Notes too - in the order of the entry.
// The core knows no preset: which fields the form shows, in what order and which of them are required
// is the app's business. Keys are unique in a form the app sends back; a form read from a foreign file
// may hold a repeated key, and it is kept as it is
#[derive(Debug, Clone, Serialize, Deserialize)]
//#[serde(rename_all = "kebab-case")]
// Using the rename will only this struct. It will not rename the child struct fields 'kebab-case' unless
// that child is also has this attribute. For now the UI layer changes to the required case
pub struct EntryFormData {
    uuid: Uuid,

    // TODO:
    // Need to change this field name to 'parent_group_uuid' as used in Entry and Group struct.
    // But this requires additional changes on the UI cljs code also
    group_uuid: Uuid,

    icon_id: i32,
    custom_icon_uuid: Option<String>,

    last_modification_time: NaiveDateTime,
    creation_time: NaiveDateTime,
    last_access_time: NaiveDateTime,
    expires: bool,
    expiry_time: NaiveDateTime,

    tags: Vec<String>,
    binary_key_values: Vec<BinaryKeyValue>,
    history_count: i32,
    // The strings of the entry, in its order
    fields: Vec<KeyValueData>,

    auto_type: AutoType,

    // This map has keys from kvd key (uppercase) and values are from kvd value that has some
    // placeholder, parsed and resolved
    #[serde(skip_deserializing)]
    parsed_fields: HashMap<String, String>,
}

impl EntryFormData {
    // Creates the EntryFormData from the given entry and is ready to be used by UI layer
    fn from_entry(entry: &Entry) -> Self {
        // All fields read from the xml content, in the order of the file
        let fields = entry
            .entry_field
            .fields
            .iter()
            .map(|kv| {
                let mut kvd: KeyValueData = kv.into();
                // Any field may hold a totp: an otp url, or the TimeOtp-* fields of KeePass
                kvd.generate_otp_on_check(&entry.parsed_otp_values);
                kvd
            })
            .collect();

        Self {
            uuid: entry.uuid,
            group_uuid: entry.parent_group_uuid,
            icon_id: entry.icon_id,
            custom_icon_uuid: entry.custom_icon_uuid.map(|u| u.to_string()),

            last_modification_time: entry.times.last_modification_time,
            creation_time: entry.times.creation_time,
            last_access_time: entry.times.last_access_time,
            expires: entry.times.expires,
            expiry_time: entry.times.expiry_time,

            auto_type: entry.auto_type.clone(),

            history_count: entry.history.entries.len() as i32,
            fields,
            tags: split_tags(&entry.tags), //entry.tags.clone()
            binary_key_values: entry.binary_key_values.clone(),
            parsed_fields: HashMap::default(),
        }
    }

    // Fails on a repeated key: the app checks the names before saving, this is the guard behind it.
    // Fields are written in the order of the form
    fn into_entry(entry_form_data: &EntryFormData) -> Result<Entry> {
        let mut entry_field = EntryField::default();
        for kvd in entry_form_data.fields.iter() {
            if entry_field.find_key_value(&kvd.key).is_some() {
                return Err(Error::DuplicateFieldKey);
            }
            entry_field.push_key_value(kvd.into());
        }

        let mut entry = Entry::new();
        entry.uuid = entry_form_data.uuid;
        entry.parent_group_uuid = entry_form_data.group_uuid;

        entry.entry_field = entry_field;
        entry.icon_id = entry_form_data.icon_id;
        entry.custom_icon_uuid = entry_form_data
            .custom_icon_uuid
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok());
        entry.tags = join_tags(&entry_form_data.tags);
        entry.times.expires = entry_form_data.expires;
        entry.times.expiry_time = entry_form_data.expiry_time;

        entry.auto_type = entry_form_data.auto_type.clone();

        // Attachment references if any
        entry.binary_key_values = entry_form_data.binary_key_values.clone();

        Ok(entry)
    }

    // Resolves all place holders for the entry fields
    pub(crate) fn place_holder_resolved_form_data(root: &Root, entry: &Entry) -> Self {
        let mut form_data = EntryFormData::from_entry(entry);
        form_data.parsed_fields =
            parsing::EntryPlaceHolderParser::resolve_place_holders(root, entry);
        form_data
    }

    // Extracts all entry field values as a map and apply any enrty field palceholder parsing
    pub(crate) fn entry_key_value_fields(
        kp: &KeepassFile,
        entry_uuid: &Uuid,
    ) -> Result<HashMap<String, String>> {
        let entry = kp
            .root
            .entry_by_id(entry_uuid)
            .ok_or(Error::NotFound("No entry Entry found for the id".into()))?;

        let (_, kvs) =
            parsing::EntryPlaceHolderParser::place_holder_resolved_entry_fields(&kp.root, entry);

        // let mut kvs = entry.field_values();
        // let parsed_fields = parsing::EntryPlaceHolderParser::resolve_place_holders(&kp.root, entry);

        // if !parsed_fields.is_empty() {
        //     for (field_name, field_value) in kvs.iter_mut() {
        //         if let Some(parsed_field_val) = parsed_fields.get(&field_name.to_uppercase()) {
        //             // field_value is &mut String and *field_value is used to update this
        //             *field_value = parsed_field_val.clone();
        //         }
        //     }
        // }

        Ok(kvs)
    }

    // The form of a new blank entry: the kdbx standard fields, as KeePass creates them
    pub fn new_form_entry(parent_group_uuid: Option<&Uuid>) -> Self {
        (&Entry::new_blank_entry(parent_group_uuid)).into()
    }
}

impl Entry {
    // When placeholder parsing is required,  all non empty entry fields are collected and
    // returned a map where keys are the UPPER CASE of entry field names.
    // Returns an empty map if there is no parsing is required
    pub(crate) fn extract_place_holders(&self) -> HashMap<String, String> {
        let mut entry_fields_with_place_holders: HashMap<String, String> = HashMap::default();

        // Checks whether any one of the entry field contain palce holder variable
        let parsing_required = self.entry_field.fields.iter().any(|kvd| {
            if !kvd.value.trim().is_empty() {
                parsing::place_holder_marker_found(&kvd.value)
            } else {
                false
            }
        });

        // if any place holder is found in any of the field values, then the field names are changed to be in UPPERCASE
        if parsing_required {
            // All non empty field values are collected to a HashMap irresespective whether the field
            // contains any placeholder or not
            entry_fields_with_place_holders = self.entry_field.fields.iter().fold(
                entry_fields_with_place_holders,
                |mut acc, kvd| {
                    if !kvd.value.trim().is_empty() {
                        // We make all keys to be in UPPER CASE before parsing
                        acc.insert(kvd.key.to_uppercase(), kvd.value.to_string());
                    }
                    acc
                },
            );
        }

        entry_fields_with_place_holders
    }
}

impl From<&Entry> for EntryFormData {
    fn from(entry: &Entry) -> Self {
        EntryFormData::from_entry(entry)
    }
}

impl TryFrom<&EntryFormData> for Entry {
    type Error = Error;

    fn try_from(entry_form_data: &EntryFormData) -> Result<Self> {
        EntryFormData::into_entry(entry_form_data)
    }
}

// The current token of one entry, for showing a code on an entry list row
//
// 'entry_uuid' is a String to match EntrySummary's own uuid, so the UI can pair a token
// with its row without converting either side. 'otp_field_name' says which field the token
// came from, so that copying it copies the right field
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EntryListOtpToken {
    pub entry_uuid: String,
    pub otp_field_name: String,
    pub token: String,
    pub ttl: u64,
    pub period: u64,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub struct EntrySummary {
    pub uuid: String,
    pub parent_group_uuid: Uuid,
    pub title: Option<String>,
    // The user name of an entry; the modification time of a history entry
    pub secondary_title: Option<String>,
    pub icon_id: i32,
    pub custom_icon_uuid: Option<String>,
    pub history_index: Option<i32>,
    pub modified_time: Option<i64>,
    pub created_time: Option<i64>,
}

impl EntrySummary {
    pub fn history_entries_summary(entry: &Entry) -> Vec<EntrySummary> {
        let mut summary_list: Vec<EntrySummary> = vec![];
        //for he in &entry.history.entries {
        for (i, he) in entry.history.entries.iter().enumerate() {
            let kv = he.entry_field.find_key_value("Title");
            //let ht = he.times.last_modification_time.format("%Y-%m-%dT%H:%M:%S");

            summary_list.push(Self {
                uuid: he.uuid.to_string(),
                // We use the entry's parent group uuid for its history
                parent_group_uuid: entry.parent_group_uuid(),
                title: kv.map(|x| x.value.clone()),
                // There is some issue of using chrono Local to get the time in local TZ in mac 12.6+ in M1
                // See more details in util.rs test. The utc time is set here and in the UI side, the datetime in local TZ shown
                secondary_title: Some(
                    he.times
                        .last_modification_time
                        .format("%Y-%m-%dT%H:%M:%S")
                        .to_string(),
                ),
                // secondary_title: Some(util::format_utc_naivedatetime_to_local(
                //     &he.times.last_modification_time,
                //     Some("%Y-%m-%d %I:%M:%S %p"),
                // )),
                icon_id: he.icon_id,
                custom_icon_uuid: he.custom_icon_uuid.map(|u| u.to_string()),
                history_index: Some(i as i32),
                modified_time: None,
                created_time: None,
            });
        }
        summary_list
    }

    // Gets the secondary title to show in addition to main title while displaying
    // an entry item in a list - a UI specific thing: the user name, place holders resolved
    pub(crate) fn secondary_title(
        entry: &Entry,
        parsed_fields: &HashMap<String, String>,
    ) -> Option<String> {
        let user_name = entry.find_kv_field_value(USER_NAME);
        parsed_fields
            .get(&USER_NAME.to_uppercase())
            .map_or(user_name, |s| Some(s.to_string()))
    }

    pub(crate) fn entry_summary_data<'a>(
        kp: &'a KeepassFile,
        entry_category: &'a categories::EntryCategory,
    ) -> Vec<EntrySummary> {
        categories::entry_by_category(kp, entry_category)
            .into_iter()
            .map(|e| EntrySummary::of(kp, e))
            .collect()
    }

    // The entry as a list shows it: the title and the user name with their place holders resolved
    pub(crate) fn of(kp: &KeepassFile, e: &Entry) -> EntrySummary {
        let parsed_fields = parsing::EntryPlaceHolderParser::resolve_place_holders(&kp.root, e);
        let title = parsed_fields
            .get(&TITLE.to_uppercase())
            .map_or_else(|| e.find_kv_field_value(TITLE), |s| Some(s.to_string()));

        let secondary_title = EntrySummary::secondary_title(e, &parsed_fields);

        Self {
            uuid: e.uuid.to_string(),
            parent_group_uuid: e.parent_group_uuid(),
            title,
            secondary_title,
            icon_id: e.icon_id,
            custom_icon_uuid: e.custom_icon_uuid.map(|u| u.to_string()),
            history_index: None,
            #[allow(deprecated)]
            modified_time: Some(e.times.last_modification_time.timestamp()),
            #[allow(deprecated)]
            created_time: Some(e.times.creation_time.timestamp()),
        }
    }

    // pub fn entry_summary_data(entries: Vec<&Entry>) -> Vec<EntrySummary> {
    //     let mut summary_list: Vec<EntrySummary> = vec![];
    //     for e in entries {
    //         let title = e.find_kv_field_value(TITLE);
    //         let secondary_title = EntrySummary::secondary_title(e);
    //         summary_list.push(Self {
    //             uuid: e.uuid.to_string(),
    //             title,
    //             secondary_title,
    //             icon_id: e.icon_id,
    //             history_index: None,
    //             modified_time: Some(e.times.last_modification_time.timestamp()),
    //             created_time: Some(e.times.creation_time.timestamp()),
    //         });
    //     }
    //     summary_list
    // }
}

#[cfg(test)]
mod tests {
    use crate::constants::entry_keyvalue_key::*;
    use crate::db_content::*;
    use crate::form_data::*;

    fn kv(key: &str, value: &str, protected: bool) -> KeyValue {
        KeyValue::from(key.into(), value.into(), protected)
    }

    fn keys(fields: &[KeyValueData]) -> Vec<&str> {
        fields.iter().map(|f| f.key.as_str()).collect()
    }

    fn value_of<'a>(fields: &'a [KeyValueData], key: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|f| f.key == key)
            .and_then(|f| f.value.as_deref())
    }

    #[test]
    fn verify_place_holder_parsing() {
        let mut root = Root::new();
        let root_group = Group::new_with_id();

        root.set_root_uuid(root_group.get_uuid());
        root.insert_to_all_groups(root_group);

        let mut parent_group = Group::new_with_id();
        parent_group.parent_group_uuid = root.root_uuid();

        root.insert_group(parent_group.clone()).unwrap();

        let mut entry = Entry::new_blank_entry(Some(&parent_group.uuid));

        entry
            .entry_field
            .update_value(TITLE, "Test {USERNAME} Title");

        entry
            .entry_field
            .update_value(USER_NAME, "My first {URL} name");

        entry
            .entry_field
            .update_value(URL, "https://www.oracle.com");

        root.insert_entry(entry.clone()).unwrap();

        let form_data = EntryFormData::place_holder_resolved_form_data(&root, &entry);

        let resolved = form_data.parsed_fields.get("USERNAME").unwrap();
        assert_eq!("My first https://www.oracle.com name", resolved);
    }

    #[test]
    fn a_new_entry_form_has_the_kdbx_standard_fields() {
        let form = EntryFormData::new_form_entry(None);

        assert_eq!(
            keys(&form.fields),
            vec![TITLE, USER_NAME, PASSWORD, URL, NOTES]
        );
        let password = form.fields.iter().find(|f| f.key == PASSWORD).unwrap();
        assert!(password.protected, "пароль защищён");
    }

    #[test]
    fn a_new_entry_has_the_kdbx_standard_fields() {
        let entry = Entry::new_blank_entry(None);
        let keys: Vec<&str> = entry
            .entry_field
            .get_key_values()
            .iter()
            .map(|kv| kv.key.as_str())
            .collect();

        assert_eq!(keys, vec![TITLE, USER_NAME, PASSWORD, URL, NOTES]);
    }

    // A foreign entry: the standard fields not in KeePass order, no Service, fields of its own
    fn foreign_entry() -> Entry {
        let mut entry = Entry::new_blank_entry(None);
        entry.entry_field = EntryField::default();
        for f in [
            kv(NOTES, "notes", false),
            kv("PIN", "1234", true),
            kv(PASSWORD, "secret", true),
            kv(TITLE, "Bank", false),
            kv("Card", "4111", false),
            kv(URL, "https://bank.example", false),
            kv(USER_NAME, "anton", false),
            kv("Answer", "blue", false),
        ] {
            entry.entry_field.insert_key_value(f);
        }
        entry
    }

    #[test]
    fn the_form_has_every_field_in_the_order_of_the_entry() {
        let form: EntryFormData = (&foreign_entry()).into();

        assert_eq!(
            keys(&form.fields),
            vec![NOTES, "PIN", PASSWORD, TITLE, "Card", URL, USER_NAME, "Answer"]
        );
        assert_eq!(value_of(&form.fields, TITLE), Some("Bank"));
        assert!(form.fields[1].protected, "защита поля - из файла");
    }

    // No "No Title" any more: an empty title is an empty string, the app labels it
    #[test]
    fn an_empty_title_is_given_as_it_is() {
        let mut entry = foreign_entry();
        entry.entry_field.update_value(TITLE, "");
        let form: EntryFormData = (&entry).into();
        assert_eq!(value_of(&form.fields, TITLE), Some(""));

        entry.entry_field.remove_key_value(TITLE);
        let form: EntryFormData = (&entry).into();
        assert!(
            value_of(&form.fields, TITLE).is_none(),
            "нет в записи - нет и в форме"
        );
    }

    #[test]
    fn the_form_round_trip_keeps_every_field_in_its_order() {
        let entry = foreign_entry();
        let form: EntryFormData = (&entry).into();
        let back = Entry::try_from(&form).unwrap();

        assert_eq!(back.entry_field, entry.entry_field);
    }

    #[test]
    fn a_repeated_key_is_in_the_form_and_a_form_with_one_is_refused() {
        let mut entry = foreign_entry();
        entry.entry_field.push_key_value(kv("PIN", "5678", true));
        let form: EntryFormData = (&entry).into();
        assert_eq!(
            keys(&form.fields).iter().filter(|k| **k == "PIN").count(),
            2
        );

        assert!(matches!(
            Entry::try_from(&form),
            Err(crate::error::Error::DuplicateFieldKey)
        ));
    }

    #[test]
    fn the_secondary_title_is_the_user_name() {
        let entry = foreign_entry();
        assert_eq!(
            EntrySummary::secondary_title(&entry, &Default::default()).as_deref(),
            Some("anton")
        );
    }

    #[test]
    fn the_form_json_has_one_list_of_fields() {
        let form = EntryFormData::new_form_entry(None);
        let json = serde_json::to_value(&form).unwrap();

        assert!(json["fields"].is_array());
        for gone in [
            "title",
            "notes",
            "preset_fields",
            "custom_fields",
            "section_fields",
            "entry_type_uuid",
        ] {
            assert!(json.get(gone).is_none(), "{} ушло из формы", gone);
        }
        let field = &json["fields"][0];
        for gone in [
            "required",
            "helper_text",
            "select_field_options",
            "standard_field",
        ] {
            assert!(field.get(gone).is_none(), "{} ушло из поля", gone);
        }
    }
}
