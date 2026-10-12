use chrono::NaiveDateTime;
use indexmap::IndexMap;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::constants::OTP_URL_PREFIX;
use crate::constants::{entry_keyvalue_key::*, EMPTY_STR};
use crate::db_content::STANDARD_PRESET_FIELDS;
use crate::db_content::{AttachmentHashValue, CustomData, Times, UnknownElements};
use crate::error::Result;
use crate::util;

use super::meta::MetaShare;
use super::otp::{CurrentOtpTokenData, OtpData, OtpSettings};
use super::time_otp;
use super::Meta;

// The fields of an entry. Kept in the order of the file - read in that order and written back in it -
// so that the custom fields of an entry are shown and saved as the user arranged them
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EntryField {
    // All fields of this entry. For easy look up, stored in a map keyed by the key of the KeyValue
    pub(crate) fields: IndexMap<String, KeyValue>,
}

impl EntryField {
    // The fields of a new entry: the kdbx standard ones, as KeePass creates them. Service of the
    // standard preset is not among them - it is written only when filled in
    fn new_entry_fields() -> EntryField {
        let mut entry_field = EntryField::default();
        entry_field.insert_key_value(KeyValue::from(TITLE.into(), String::default(), false));
        for f in STANDARD_PRESET_FIELDS.iter().filter(|f| f.key != SERVICE) {
            entry_field.insert_key_value(KeyValue::from(
                f.key.into(),
                String::default(),
                f.protected,
            ));
        }
        entry_field.insert_key_value(KeyValue::from(NOTES.into(), String::default(), false));
        entry_field
    }

    /// Called after reading the field KeyValue while parsing the XML content
    pub fn insert_key_value(&mut self, kv: KeyValue) {
        self.fields.insert(kv.key.clone(), kv);
    }

    pub fn insert_key_values(&mut self, kvs: Vec<KeyValue>) {
        for kv in kvs {
            self.fields.insert(kv.key.clone(), kv);
        }
    }

    /// Called to get all fields of this entry and used while writing to XML content
    pub fn get_key_values(&self) -> Vec<&KeyValue> {
        // In the order of the file
        self.fields.values().collect()
    }

    // Memory-security lock: volatile-zero every field value in place (all
    // fields, not only protected ones - Notes/Title/URL can be sensitive too). Used
    // before the content object graph is dropped on lock so plaintext does not
    // linger in freed heap.
    pub(crate) fn zeroize_values(&mut self) {
        use zeroize::Zeroize;
        for kv in self.fields.values_mut() {
            kv.value.zeroize();
        }
    }

    pub fn find_key_value(&self, key: &str) -> Option<&KeyValue> {
        self.fields.values().find(|f| f.key == key)
    }

    // Drops a field from the entry. The removed value is zeroized on the way out: a totp secret
    // is one of the things removed this way (see db_content/time_otp.rs)
    pub(crate) fn remove_key_value(&mut self, key: &str) -> Option<KeyValue> {
        use zeroize::Zeroize;
        // shift_remove keeps the order of the rest of the fields
        self.fields.shift_remove(key).map(|mut kv| {
            kv.value.zeroize();
            kv
        })
    }

    // finds a KeyValue from the 'fields' map and updates its 'value' field with the passed value
    // The update is done only if an entry is found
    pub fn update_value(&mut self, key: &str, value: &str) {
        self.fields
            .entry(key.to_string())
            .and_modify(|e| e.value = value.into());
    }
}

//#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct Entry {
    pub(crate) uuid: Uuid,

    // The parent group uuid to refer back the group if required
    pub(crate) parent_group_uuid: Uuid,

    pub(crate) icon_id: i32,

    pub(crate) times: Times,

    pub(crate) tags: String,

    // KeePass / KeePassXC entry properties our UI does not edit - kept as read from the file.
    // Colors are "#RRGGBB" (empty = none), override_url is the command used to open the URL
    pub(crate) foreground_color: String,
    pub(crate) background_color: String,
    pub(crate) override_url: String,
    // KDBX 4.1: false = excluded from password quality reports
    pub(crate) quality_check: bool,
    // KDBX 4.1: the group the entry was in before its last move (nil = none)
    pub(crate) previous_parent_group: Uuid,

    // entry_field contains all KeyValues
    pub(crate) entry_field: EntryField,

    pub(crate) binary_key_values: Vec<BinaryKeyValue>,

    pub(crate) custom_data: CustomData,

    pub(crate) custom_icon_uuid: Option<Uuid>,

    pub(crate) auto_type: AutoType,

    // Elements of <Entry> the core does not know - written back as read (history copies too)
    pub(crate) unknown_elements: UnknownElements,

    pub(crate) history: History,

    // Need to use #[serde(skip)] if we use Entry 'Serialize'
    pub(crate) meta_share: Arc<MetaShare>,

    //pub(crate) parsed_otp_values: Option<HashMap<String, ParsedOtpData>>,
    pub(crate) parsed_otp_values: Option<HashMap<String, OtpData>>,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
            && self.parent_group_uuid == other.parent_group_uuid
            && self.icon_id == other.icon_id
            && self.times == other.times
            && self.tags == other.tags
            && self.foreground_color == other.foreground_color
            && self.background_color == other.background_color
            && self.override_url == other.override_url
            && self.quality_check == other.quality_check
            && self.previous_parent_group == other.previous_parent_group
            && self.entry_field == other.entry_field
            && self.binary_key_values == other.binary_key_values
            && self.custom_data == other.custom_data
            && self.custom_icon_uuid == other.custom_icon_uuid
            && self.auto_type == other.auto_type
            && self.unknown_elements == other.unknown_elements
            && self.history.entries.len() == other.history.entries.len()
            && self.history == other.history
            // && self.meta_share == other.meta_share
            && self.parsed_otp_values == other.parsed_otp_values
    }
}

impl Entry {
    pub(crate) fn new() -> Self {
        Entry {
            uuid: Uuid::default(),
            parent_group_uuid: Uuid::default(),
            icon_id: i32::default(),
            times: Times::new(),
            tags: String::default(),
            foreground_color: String::default(),
            background_color: String::default(),
            override_url: String::default(),
            quality_check: true,
            previous_parent_group: Uuid::default(),
            entry_field: EntryField::default(),
            //key_values: vec![],
            binary_key_values: vec![],
            custom_data: CustomData::default(),
            custom_icon_uuid: None,
            auto_type: AutoType::default(),
            unknown_elements: UnknownElements::default(),
            //history has a list of previous entries and those entries listed will have its 'history' empty
            history: History::default(),
            meta_share: Arc::default(),
            parsed_otp_values: None,
        }
    }

    #[inline]
    pub(crate) fn get_uuid(&self) -> Uuid {
        self.uuid
    }

    #[inline]
    pub(crate) fn parent_group_uuid(&self) -> Uuid {
        self.parent_group_uuid
    }

    #[inline]
    pub(crate) fn set_parent_group_uuid(&mut self, parent_group_uuid: &Uuid) -> &mut Self {
        self.parent_group_uuid = *parent_group_uuid;
        self
    }

    #[inline]
    pub(crate) fn last_modification_time(&self) -> NaiveDateTime {
        self.times.last_modification_time
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn update_modification_time_now(&mut self) -> &mut Self {
        self.times.update_modification_time_now();
        self
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn update_modification_time(
        &mut self,
        modification_time: NaiveDateTime,
    ) -> &mut Self {
        self.times.update_modification_time(modification_time);
        self
    }

    #[inline]
    pub(crate) fn location_changed(&self) -> NaiveDateTime {
        self.times.location_changed
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn histories(&self) -> &Vec<Entry> {
        &self.history.entries
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn set_histories(&mut self, history_entries: &[Entry]) -> &mut Self {
        self.history.entries = history_entries.to_owned();
        self
    }

    // A new entry of the standard preset
    pub(crate) fn new_blank_entry(parent_group_uuid: Option<&Uuid>) -> Entry {
        let mut entry = Entry::new();
        entry.uuid = uuid::Uuid::new_v4();
        entry.entry_field = EntryField::new_entry_fields();
        if let Some(gid) = parent_group_uuid {
            entry.parent_group_uuid = *gid;
            // IMPORTANT: The caller needs to set the parent Group uuid later if not passed
        }
        entry
    }

    // Any entry specific custom data parsing and setting in Entry to be done here
    pub(crate) fn after_xml_reading(&mut self, meta: &Meta) {
        self.meta_share = Arc::clone(&meta.meta_share);

        // Otp fields are to be parsed from the url
        self.parse_all_otp_fields();
    }

    pub(crate) fn before_xml_writing(&mut self) {
        // Nothing of the entry is kept outside its own elements: CustomData is written as read
    }

    pub(crate) fn update(&mut self, mut updated_entry: Entry) {
        // The 'updated_entry' created in EntryDataForm will not have meta_share set
        // and we need to set it here
        updated_entry.meta_share = Arc::clone(&self.meta_share);

        // First we need to create history entries before any updates to the existing entry
        let histories = self.create_histories();

        // Change the last modified time
        // Only expiry related information is copied from the incoming updated_entry.times
        self.times.expires = updated_entry.times.expires;
        self.times.expiry_time = updated_entry.times.expiry_time;

        let now = util::now_utc();
        self.times.last_access_time = now;
        self.times.last_modification_time = now;

        self.binary_key_values = updated_entry.binary_key_values;
        self.history = History { entries: histories };
        self.parent_group_uuid = updated_entry.parent_group_uuid;
        self.icon_id = updated_entry.icon_id;
        self.custom_icon_uuid = updated_entry.custom_icon_uuid;
        self.tags = updated_entry.tags;

        // The form does not edit the obfuscation mode: a client that drops the field from the
        // AutoType JSON must not reset the value read from the file
        let data_transfer_obfuscation = self.auto_type.data_transfer_obfuscation;
        self.auto_type = updated_entry.auto_type;
        self.auto_type.data_transfer_obfuscation = data_transfer_obfuscation;

        self.entry_field = updated_entry.entry_field;

        self.parse_all_otp_fields();
    }

    // Called to ensure the otp fields are parsed when a new entry is created
    pub(crate) fn complete_insert(&mut self) {
        self.parse_all_otp_fields();
    }

    pub(crate) fn set_attachment_hashes(
        &mut self,
        attachment_hash_indexed: &HashMap<i32, (AttachmentHashValue, usize)>,
    ) {
        // First we set all hashes for an entry followed by the entries found in its history
        // binary_key_values is empty if the entry does not have any attachment
        for bv in &mut self.binary_key_values {
            if let Some(h) = attachment_hash_indexed.get(&bv.index_ref) {
                bv.data_hash = h.0;
                bv.data_size = h.1;
            }
        }
        // We call the history entries for this entry.
        // IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &mut self.history.entries {
            e.set_attachment_hashes(attachment_hash_indexed);
        }
    }

    // Memory-security lock: volatile-zero this entry's field values and all
    // of its history entries' values before the content is dropped on lock.
    pub(crate) fn zeroize_sensitive_content(&mut self) {
        self.entry_field.zeroize_values();
        self.unknown_elements.zeroize_text();
        for e in &mut self.history.entries {
            e.zeroize_sensitive_content();
        }
    }

    // Called after forming inner header binary data and before writing xml as bytes
    // to set the correct attachment index based on the attachment hash value
    // The arg 'hash_index_ref' is a newly prepared mappping
    pub fn set_attachment_index_refs(
        &mut self,
        hash_index_ref: &HashMap<AttachmentHashValue, i32>,
    ) {
        // First we set all index refs for an entry followed by the entries found in its history
        for bv in &mut self.binary_key_values {
            if let Some(idx) = hash_index_ref.get(&bv.data_hash) {
                bv.index_ref = *idx;
            } else {
                log::error!(
                    "Index ref for the attachment with hash {} and name {} of entry {:?} is not found after writing to inner header",
                    bv.data_hash,
                    bv.key,
                    self.uuid
                );
            }
        }
        // We call also the histories entries.
        // IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &mut self.history.entries {
            e.set_attachment_index_refs(hash_index_ref);
        }
    }

    // Gets the hash values of all attachments from this entry and the entries found in history field
    pub(crate) fn get_attachment_hashes(&self, hashes: &mut Vec<u64>) {
        // First we collect all hashes from an entry followed by the entries found in its history
        //let mut hashes = vec![];
        for bv in &self.binary_key_values {
            hashes.push(bv.data_hash);
        }
        // We call also the histories entries.
        //IMPORATNT: It is assumed each entry found in historty.entries should have empty history
        for e in &self.history.entries {
            e.get_attachment_hashes(hashes);
        }
    }

    // May return empty string if no title is present
    pub(crate) fn title(&self) -> String {
        self.find_kv_field_value(TITLE)
            .as_ref()
            .map_or_else(|| EMPTY_STR, |s| s)
            .to_string()
    }

    // Finds a field's value from KeyValue
    pub(crate) fn find_kv_field_value(&self, name: &str) -> Option<String> {
        self.entry_field
            .find_key_value(name)
            .map(|x| x.value.clone())
    }

    // Collects all entry field names and values (not in any particular order)
    pub(crate) fn field_values(&self) -> HashMap<String, String> {
        self.entry_field
            .get_key_values()
            .into_iter()
            .map(|k| (k.key.clone(), k.value.clone()))
            .collect()
    }

    // Checks the whether the value of a field starts with otp url and parses if it is an valid otp url
    // and stores in the map with the field name as key and parsed value as value
    // However if parsing a otp url fails, then nothing is set for that field in this map
    //
    // Entries written by the original KeePass 2.47+ keep their totp in separate fields instead of
    // an url (see db_content/time_otp.rs); those are read as a second source below and land in the
    // same map, keyed by the field holding the secret. Everything downstream - the entry form, the
    // list row and the polling - addresses a token by its field name and so needs no change
    fn parse_all_otp_fields(&mut self) {
        let mut otp_vals: HashMap<String, OtpData> = self
            .entry_field
            .get_key_values()
            .into_iter()
            .filter_map(|k| {
                if k.value.starts_with(OTP_URL_PREFIX) {
                    match OtpData::from_url(&k.value) {
                        Ok(parsed_otp_data) => Some((k.key.clone(), parsed_otp_data)),
                        Err(e) => {
                            info!("OtpUrl Parsing Failed with error {}", e);
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect();

        // A field that cannot be used is skipped with a log line, exactly as an unparseable url is:
        // the entry still opens, and its fields are left untouched so saving cannot damage them
        if let Some(parsed) = time_otp::parse(&self.field_values()) {
            match parsed
                .and_then(|t| OtpData::from_otp_settings(&t.settings).map(|d| (t.secret_field, d)))
            {
                Ok((secret_field, otp_data)) => {
                    otp_vals.insert(secret_field.to_string(), otp_data);
                }
                Err(e) => info!("TimeOtp fields parsing failed with error {}", e),
            }
        }

        if !otp_vals.is_empty() {
            self.parsed_otp_values = Some(otp_vals);
        } else {
            self.parsed_otp_values = None;
        }
    }

    // Sets the entry's 2fa, in the format the entry already uses: an entry that came from the
    // original KeePass keeps its TimeOtp-* fields (and the secret encoding they were in), an entry
    // holding an `otp` url keeps the url, and an entry with no 2fa yet gets an `otp` url - the form
    // KeePassXC, KeePassDX and we ourselves read. Converting a foreign entry to the other format
    // would break its 2fa in the program the user came from (Step 17 - do not rewrite foreign data).
    //
    // The settings are validated before anything is written, so a bad secret or an unsupported
    // period leaves the entry untouched. Additional otp fields of an entry are not touched here:
    // they are edited through the entry form like any other field.
    pub(crate) fn set_otp(&mut self, otp_settings: &OtpSettings) -> Result<()> {
        let otp_data = OtpData::from_otp_settings(otp_settings)?;

        // A TimeOtp entry keeps its format whether or not the old value could be read
        match time_otp::secret_encoding(&self.field_values()) {
            Some(encoding) => time_otp::write(&mut self.entry_field, &otp_data, encoding)?,
            None => self.set_otp_url(&otp_data.get_url()),
        }

        self.parse_all_otp_fields();
        Ok(())
    }

    // Removes the entry's 2fa without leaving a tail: all TimeOtp fields go, and so does the `otp`
    // field - it is not a field of the preset, and an empty one would stay in the form as a custom
    // field holding nothing (Step 43)
    pub(crate) fn remove_otp(&mut self) {
        time_otp::remove_all(&mut self.entry_field);
        self.entry_field.remove_key_value(OTP);
        self.parse_all_otp_fields();
    }

    fn set_otp_url(&mut self, url: &str) {
        if self.entry_field.find_key_value(OTP).is_some() {
            self.entry_field.update_value(OTP, url);
        } else {
            self.entry_field.insert_key_value(KeyValue::from(
                OTP.to_string(),
                url.to_string(),
                true,
            ));
        }
    }

    pub(crate) fn current_otp_token_data(
        &self,
        otp_field_name: &str,
    ) -> Option<CurrentOtpTokenData> {
        // as_ref() is to get Option<&HashMap<String, OtpData>>
        // first flatten Option<Option<&OtpData>> -> Option<&OtpData>
        // second flatten Option<Option<CurrentOtpTokenData>> -> Option<CurrentOtpTokenData>
        self.parsed_otp_values
            .as_ref()
            .and_then(|m| m.get(otp_field_name))
            .and_then(|pd| pd.current_otp_token_data().ok())
    }

    // The one otp field whose token represents this entry in a list, with its current token
    //
    // An entry may hold several otp fields - the standard one plus any in the additional
    // one-time passwords section - and a list row has room for a single code. Where the
    // choice is not obvious nothing is returned: showing one of several codes with no way
    // to tell which field it came from invites copying the wrong one, and the row falling
    // back to no code at all leaves the user to open the entry, as before
    pub(crate) fn list_otp_token_data(&self) -> Option<(String, CurrentOtpTokenData)> {
        let parsed = self.parsed_otp_values.as_ref()?;

        // The standard field wins whenever it is present and usable
        if let Some(data) = self.current_otp_token_data(OTP) {
            return Some((OTP.to_string(), data));
        }

        // Otherwise only a single custom field is unambiguous enough to show
        let mut names = parsed.keys();
        let only_name = match (names.next(), names.next()) {
            (Some(name), None) => name.clone(),
            _ => return None,
        };

        self.current_otp_token_data(&only_name)
            .map(|data| (only_name, data))
    }
}

impl Entry {
    // Adds the current entry to the existing histories, for the merge to work on
    pub(crate) fn create_histories_to_merge(&mut self) -> Vec<Entry> {
        self.create_histories()
    }

    pub(crate) fn histories_to_merge(&mut self) -> Vec<Entry> {
        self.histories().clone()
    }

    pub(crate) fn set_merged_histories(&mut self, history_entries: &[Entry]) {
        self.history.entries = history_entries.to_owned();
    }

    // Checks whether the other entry is in the current entry's history or not
    pub(crate) fn found_in_history(&self, other_entry: &Entry) -> bool {
        self.histories()
            .iter()
            .find(|he| {
                he.uuid == other_entry.uuid
                    && he.last_modification_time() == other_entry.last_modification_time()
            })
            .is_some()
    }
}

// All history entries related methods implemented on Entry are organized separately
// here for easy maintenance
impl Entry {
    // Size of the entry as KeePass computes it (KeePassLib PwEntry.GetSize): an in-memory estimate,
    // 2 bytes per UTF-16 char plus fixed per-item overheads. Used for HistoryMaxSize so that the same
    // database is trimmed the same way here and in KeePass. Attachments count in every version that
    // references them, although the file stores each attachment once
    pub(crate) fn keepass_size(&self) -> u64 {
        fn chars(s: &str) -> u64 {
            s.encode_utf16().count() as u64
        }

        let mut bytes: u64 = 276;
        let mut char_count: u64 = 0;

        bytes += self.entry_field.fields.len() as u64 * 40;
        for kv in self.entry_field.fields.values() {
            char_count += chars(&kv.key) + chars(&kv.value);
        }

        bytes += self.binary_key_values.len() as u64 * 65;
        for bkv in &self.binary_key_values {
            char_count += chars(&bkv.key);
            bytes += bkv.data_size as u64;
        }

        char_count += self.auto_type.default_sequence.as_deref().map_or(0, chars);
        bytes += self.auto_type.associations.len() as u64 * 24;
        for a in &self.auto_type.associations {
            char_count += chars(&a.window) + a.key_stroke_sequence.as_deref().map_or(0, chars);
        }

        bytes += self.history.entries.len() as u64 * 8;
        for h in &self.history.entries {
            bytes += h.keepass_size();
        }

        char_count += chars(&self.override_url);

        let tags = crate::db_content::split_tags(&self.tags);
        bytes += tags.len() as u64 * 8;
        for t in &tags {
            char_count += chars(t);
        }

        let items = self.custom_data.get_items();
        bytes += items.len() as u64 * 16;
        for item in items {
            char_count += chars(&item.key) + chars(&item.value);
        }

        bytes + char_count * 2
    }

    // Applies history limits to this entry's current history (KeePass PwEntry.MaintainBackups).
    // The limits are passed in: entries brought in by a merge may still share the source's MetaShare.
    // Returns true if versions were removed
    pub(crate) fn maintain_history(&mut self, max_items: i32, max_size: i64) -> bool {
        let before = self.history.entries.len();
        Self::trim_histories(&mut self.history.entries, max_items, max_size);
        self.history.entries.len() != before
    }

    // KeePass semantics: a negative limit means no limit; the count is applied first, then the size;
    // the version removed is the one with the oldest last modification time, not the first in the list
    // (after a merge the list is not in time order)
    fn trim_histories(histories: &mut Vec<Entry>, max_items: i32, max_size: i64) {
        let remove_oldest = |histories: &mut Vec<Entry>| {
            let oldest = histories
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.times.last_modification_time)
                .map(|(i, _)| i);
            if let Some(i) = oldest {
                histories.remove(i);
            }
        };

        let before = histories.len();
        if max_items >= 0 {
            while histories.len() > max_items as usize {
                remove_oldest(histories);
            }
        }
        if max_size >= 0 {
            while histories.iter().map(Entry::keepass_size).sum::<u64>() > max_size as u64 {
                remove_oldest(histories);
            }
        }
        if histories.len() != before {
            debug!("Removed {} history items", before - histories.len());
        }
    }

    // Called to recreate the history entries. The existing entry before update is
    // added to the history and returned
    pub(crate) fn create_histories(&mut self) -> Vec<Entry> {
        let mut existing_entry_copy: Entry = self.clone();

        // Make a copy of the existing history entries
        let mut histories: Vec<Entry> = existing_entry_copy.history.entries;

        // The existing_entry_copy should not have any history entries before adding to h
        existing_entry_copy.history.entries = vec![];

        // Add the existing_entry_copy as last item in the history list
        histories.push(existing_entry_copy);

        // Like KeePass: add the backup first, then trim (PwEntry.CreateBackup + MaintainBackups)
        Self::trim_histories(
            &mut histories,
            self.meta_share.history_max_items(),
            self.meta_share.history_max_size(),
        );

        // This histories will set to the new updated entry
        histories
    }

    // Gets a history entry
    pub(crate) fn history_entry_by_index(&self, index: i32) -> Option<Entry> {
        let he = self.history.entries.get(index as usize).cloned();
        he.map(|mut e1| {
            // Need to set the appropriate group uuid to the history entry
            e1.parent_group_uuid = self.parent_group_uuid;
            e1.meta_share = Arc::clone(&self.meta_share);
            e1
        })
    }

    pub(crate) fn delete_history_entry_by_index(&mut self, index: i32) {
        let idx = index as usize;
        if idx < self.history.entries.len() {
            self.history.entries.remove(idx);
        } else {
            log::error!(
                "delete_history_entry_by_index called with invalid index {}",
                idx
            );
        }
    }

    // Deletes all the history entries of an entry
    pub(crate) fn delete_history_entries(&mut self) {
        self.history.entries.clear();
    }
}

// One string field of an entry, as in the file
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyValue {
    pub(crate) key: String,
    pub(crate) value: String,
    pub(crate) protected: bool,
}

// Written by hand: the derived one would print the secret - see crate::redacted
impl std::fmt::Debug for KeyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyValue")
            .field("key", &self.key)
            .field("value", &crate::redacted::Redacted)
            .field("protected", &self.protected)
            .finish()
    }
}

impl KeyValue {
    pub(crate) fn new() -> Self {
        KeyValue {
            key: String::default(),
            value: String::default(),
            protected: bool::default(),
        }
    }

    pub(crate) fn from(key: String, value: String, protected: bool) -> Self {
        KeyValue {
            key,
            value,
            protected,
        }
    }

    pub fn key(&self) -> &String {
        &self.key
    }

    pub fn value(&self) -> &String {
        &self.value
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryKeyValue {
    /// Attachment name
    pub(crate) key: String,
    /// An empty tag with Ref attribute
    pub(crate) value: String,
    /// This is the index into the Inner header Binaries collection for this attachment
    pub(crate) index_ref: i32,
    #[serde(with = "util::from_or_to::string")]
    pub(crate) data_hash: AttachmentHashValue,
    pub(crate) data_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutoType {
    pub(crate) enabled: bool,
    // None means inherits the parent group's sequence if enabled
    // default_sequence can be set at entry level overriding the inherited one
    pub(crate) default_sequence: Option<String>,
    pub(crate) associations: Vec<Association>,
    // KeePass: 0 = none, 1 = two-channel auto-type obfuscation. Not edited by our UI -
    // kept from the file (see Entry::update)
    #[serde(default)]
    pub(crate) data_transfer_obfuscation: i32,
}

impl Default for AutoType {
    fn default() -> Self {
        Self {
            enabled: true,
            default_sequence: None,
            associations: vec![],
            data_transfer_obfuscation: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Association {
    pub(crate) window: String,
    pub(crate) key_stroke_sequence: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq)]
//#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct History {
    // History has a list of previous entries
    pub(crate) entries: Vec<Entry>,
}

#[cfg(test)]
mod tests {
    use super::{BinaryKeyValue, Entry, EntryField, KeyValue, OtpSettings};
    use uuid::Uuid;

    fn make_kv(key: &str, value: &str, protected: bool) -> KeyValue {
        KeyValue {
            key: key.into(),
            value: value.into(),
            protected,
        }
    }

    // EntryField tests

    #[test]
    fn entry_field_insert_and_find_key_value() {
        let mut ef = EntryField::default();
        ef.insert_key_value(make_kv("Title", "My Bank", false));
        let found = ef.find_key_value("Title");
        assert!(found.is_some());
        assert_eq!(found.unwrap().value, "My Bank");
    }

    #[test]
    fn entry_field_find_missing_key_returns_none() {
        let ef = EntryField::default();
        assert!(ef.find_key_value("NonExistent").is_none());
    }

    #[test]
    fn entry_field_insert_multiple_keys() {
        let mut ef = EntryField::default();
        ef.insert_key_value(make_kv("Title", "Bank", false));
        ef.insert_key_value(make_kv("UserName", "alice", false));
        ef.insert_key_value(make_kv("Password", "s3cr3t", true));
        assert_eq!(ef.get_key_values().len(), 3);
    }

    #[test]
    fn entry_field_update_value_existing_key() {
        let mut ef = EntryField::default();
        ef.insert_key_value(make_kv("Title", "Old Title", false));
        ef.update_value("Title", "New Title");
        assert_eq!(ef.find_key_value("Title").unwrap().value, "New Title");
    }

    #[test]
    fn entry_field_update_value_missing_key_is_noop() {
        let mut ef = EntryField::default();
        ef.insert_key_value(make_kv("Title", "Unchanged", false));
        ef.update_value("DoesNotExist", "ShouldNotAppear");
        // Title must remain unchanged and the missing key must not be inserted
        assert_eq!(ef.find_key_value("Title").unwrap().value, "Unchanged");
        assert!(ef.find_key_value("DoesNotExist").is_none());
    }

    #[test]
    fn entry_field_insert_key_values_batch() {
        let mut ef = EntryField::default();
        let kvs = vec![
            make_kv("Title", "Gmail", false),
            make_kv("UserName", "user@gmail.com", false),
        ];
        ef.insert_key_values(kvs);
        assert!(ef.find_key_value("Title").is_some());
        assert!(ef.find_key_value("UserName").is_some());
    }

    // Entry tests

    #[test]
    fn entry_new_has_default_uuid() {
        let e = Entry::new();
        assert_eq!(e.uuid, Uuid::default());
    }

    #[test]
    fn entry_new_has_default_parent_uuid() {
        let e = Entry::new();
        assert_eq!(e.parent_group_uuid, Uuid::default());
    }

    #[test]
    fn entry_new_has_no_otp_values() {
        let e = Entry::new();
        assert!(e.parsed_otp_values.is_none());
    }

    #[test]
    fn entry_new_has_empty_tags() {
        let e = Entry::new();
        assert!(e.tags.is_empty());
    }

    #[test]
    fn entry_set_parent_group_uuid() {
        let mut e = Entry::new();
        let parent_id = Uuid::new_v4();
        e.set_parent_group_uuid(&parent_id);
        assert_eq!(e.parent_group_uuid(), parent_id);
    }

    #[test]
    fn entry_get_uuid_matches_internal_uuid() {
        let mut e = Entry::new();
        e.uuid = Uuid::new_v4();
        assert_eq!(e.get_uuid(), e.uuid);
    }

    #[test]
    fn entry_new_has_empty_attachments() {
        let e = Entry::new();
        assert!(e.binary_key_values.is_empty());
    }

    #[test]
    fn binary_key_value_key_field() {
        let bkv = BinaryKeyValue {
            key: "document.pdf".into(),
            value: String::default(),
            index_ref: 0,
            data_hash: 0,
            data_size: 0,
        };
        assert_eq!(bkv.key, "document.pdf");
    }

    #[test]
    fn entry_new_has_empty_history() {
        let e = Entry::new();
        assert!(e.histories().is_empty());
    }

    // Entry::list_otp_token_data - which single otp field represents an entry on a list row

    fn otp_url(secret: &str) -> String {
        format!("otpauth://totp/OneKeePass:test?secret={}&period=30", secret)
    }

    // Builds an entry holding the given otp fields, parsed as loading a database would
    fn entry_with_otp_fields(fields: &[(&str, &str)]) -> Entry {
        let mut e = Entry::new();
        for (key, value) in fields {
            e.entry_field.insert_key_value(make_kv(key, value, true));
        }
        e.parse_all_otp_fields();
        e
    }

    #[test]
    fn list_otp_token_data_uses_the_standard_field() {
        let e = entry_with_otp_fields(&[("otp", &otp_url("JBSWY3DPEHPK3PXP"))]);
        let (field_name, data) = e.list_otp_token_data().unwrap();
        assert_eq!(field_name, "otp");
        assert_eq!(data.period, 30);
        assert!(!data.token.is_empty());
    }

    #[test]
    fn list_otp_token_data_uses_a_lone_custom_field() {
        let e = entry_with_otp_fields(&[("My Git OTP Code", &otp_url("JBSWY3DPEHPK3PXP"))]);
        let (field_name, _data) = e.list_otp_token_data().unwrap();
        assert_eq!(field_name, "My Git OTP Code");
    }

    #[test]
    fn list_otp_token_data_prefers_the_standard_field_over_a_custom_one() {
        let e = entry_with_otp_fields(&[
            ("My Git OTP Code", &otp_url("JBSWY3DPEHPK3PXP")),
            ("otp", &otp_url("GEZDGNBVGY3TQOJQ")),
        ]);
        let (field_name, _data) = e.list_otp_token_data().unwrap();
        assert_eq!(field_name, "otp");
    }

    // Two custom fields and no standard one is the ambiguous case: showing either code
    // would give the user no way to tell which field it came from
    #[test]
    fn list_otp_token_data_is_none_for_two_custom_fields() {
        let e = entry_with_otp_fields(&[
            ("My Git OTP Code", &otp_url("JBSWY3DPEHPK3PXP")),
            ("My AWS OTP Code", &otp_url("GEZDGNBVGY3TQOJQ")),
        ]);
        assert!(e.list_otp_token_data().is_none());
    }

    #[test]
    fn list_otp_token_data_is_none_without_any_otp_field() {
        let e = entry_with_otp_fields(&[("UserName", "user@example.com")]);
        assert!(e.list_otp_token_data().is_none());
    }

    // An unparseable url leaves no parsed value behind, so the entry has nothing to show
    #[test]
    fn list_otp_token_data_is_none_for_an_unparseable_url() {
        let e = entry_with_otp_fields(&[("otp", "otpauth://totp/no-secret-here")]);
        assert!(e.list_otp_token_data().is_none());
    }
    // TimeOtp fields of the original KeePass 2.47+ (Step 21) - see db_content/time_otp.rs

    // The RFC 6238 test secret "12345678901234567890" as Base32
    const TIME_OTP_TEST_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn a_time_otp_entry_gives_a_token_keyed_by_its_secret_field() {
        let e = entry_with_otp_fields(&[("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET)]);

        let token = e
            .current_otp_token_data("TimeOtp-Secret-Base32")
            .expect("a token is generated from the TimeOtp fields");
        assert_eq!(token.token.len(), 6);
        assert_eq!(token.period, 30);
    }

    #[test]
    fn the_time_otp_period_and_length_reach_the_token() {
        let e = entry_with_otp_fields(&[
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
            ("TimeOtp-Period", "60"),
            ("TimeOtp-Length", "8"),
        ]);

        let token = e.current_otp_token_data("TimeOtp-Secret-Base32").unwrap();
        assert_eq!(token.token.len(), 8);
        assert_eq!(token.period, 60);
    }

    #[test]
    fn an_entry_holding_both_formats_gives_a_token_for_each_field() {
        let e = entry_with_otp_fields(&[
            ("otp", &otp_url(TIME_OTP_TEST_SECRET)),
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
        ]);

        assert!(e.current_otp_token_data("otp").is_some());
        assert!(e.current_otp_token_data("TimeOtp-Secret-Base32").is_some());
    }

    // One list row has room for a single code, and the url field stays the one it shows
    #[test]
    fn a_list_row_prefers_the_url_field_when_an_entry_holds_both_formats() {
        let e = entry_with_otp_fields(&[
            ("otp", &otp_url(TIME_OTP_TEST_SECRET)),
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
        ]);

        let (field_name, _data) = e.list_otp_token_data().expect("one code for the row");
        assert_eq!(field_name, "otp");
    }

    #[test]
    fn unusable_time_otp_fields_leave_the_entry_without_a_token() {
        // An undecodable secret, and a period outside what the core supports (1 - 60 seconds)
        for fields in [
            vec![("TimeOtp-Secret-Base32", "not base32 !!")],
            vec![
                ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
                ("TimeOtp-Period", "90"),
            ],
        ] {
            let e = entry_with_otp_fields(&fields);
            assert!(
                e.parsed_otp_values.is_none(),
                "{:?} must not produce a token",
                fields
            );
            // The fields themselves are left alone, so saving cannot damage them
            assert!(e
                .entry_field
                .find_key_value("TimeOtp-Secret-Base32")
                .is_some());
        }
    }
    // Writing and removing a 2fa (Step 21 p.3) - Entry::set_otp / Entry::remove_otp

    fn settings(secret: &str, period: Option<u64>, digits: Option<usize>) -> OtpSettings {
        OtpSettings {
            secret_or_url: secret.to_string(),
            period,
            digits,
            hash_algorithm: None,
        }
    }

    fn value_of(e: &Entry, field: &str) -> Option<String> {
        e.entry_field
            .find_key_value(field)
            .map(|kv| kv.value.clone())
    }

    #[test]
    fn a_new_2fa_is_written_as_an_otpauth_url() {
        let mut e = entry_with_otp_fields(&[("UserName", "user@example.com")]);
        e.set_otp(&settings(TIME_OTP_TEST_SECRET, None, None))
            .unwrap();

        let url = value_of(&e, "otp").expect("the otp field is created");
        assert!(url.starts_with("otpauth://totp/"), "{}", url);
        assert!(url.contains(TIME_OTP_TEST_SECRET), "{}", url);
        assert!(e.current_otp_token_data("otp").is_some());
        // The entry did not gain any KeePass fields it did not have
        assert!(value_of(&e, "TimeOtp-Secret-Base32").is_none());
    }

    #[test]
    fn a_keepass_entry_keeps_its_own_format_and_secret_encoding() {
        // The RFC 6238 secret as hex, the way the original KeePass may have stored it
        let mut e = entry_with_otp_fields(&[(
            "TimeOtp-Secret-Hex",
            "3132333435363738393031323334353637383930",
        )]);

        // A different secret, entered by the user in our app
        e.set_otp(&settings("JBSWY3DPEHPK3PXP", None, None))
            .unwrap();

        assert!(
            value_of(&e, "otp").is_none(),
            "a KeePass entry must not be converted to an url - that would break it in KeePass"
        );
        let hex = value_of(&e, "TimeOtp-Secret-Hex").expect("the secret stays in its own field");
        assert_eq!(
            hex, "48656c6c6f21deadbeef",
            "the secret is rewritten as hex"
        );
        assert!(e.current_otp_token_data("TimeOtp-Secret-Hex").is_some());
    }

    #[test]
    fn keepass_fields_equal_to_the_default_are_left_out_and_others_are_written() {
        let mut e = entry_with_otp_fields(&[
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
            ("TimeOtp-Period", "60"),
            ("TimeOtp-Length", "8"),
        ]);

        // Back to the KeePass defaults: the fields go away rather than holding "30" and "6"
        e.set_otp(&settings(TIME_OTP_TEST_SECRET, Some(30), Some(6)))
            .unwrap();
        assert!(value_of(&e, "TimeOtp-Period").is_none());
        assert!(value_of(&e, "TimeOtp-Length").is_none());

        // And back again
        e.set_otp(&settings(TIME_OTP_TEST_SECRET, Some(45), Some(7)))
            .unwrap();
        assert_eq!(value_of(&e, "TimeOtp-Period").unwrap(), "45");
        assert_eq!(value_of(&e, "TimeOtp-Length").unwrap(), "7");
    }

    #[test]
    fn a_second_stale_secret_field_does_not_survive_an_update() {
        let mut e = entry_with_otp_fields(&[
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
            (
                "TimeOtp-Secret-Hex",
                "3132333435363738393031323334353637383930",
            ),
        ]);

        e.set_otp(&settings("JBSWY3DPEHPK3PXP", None, None))
            .unwrap();

        assert_eq!(
            value_of(&e, "TimeOtp-Secret-Base32").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(
            value_of(&e, "TimeOtp-Secret-Hex").is_none(),
            "an entry must not be left holding two different secrets"
        );
    }

    #[test]
    fn an_unusable_secret_leaves_the_entry_untouched() {
        let mut e = entry_with_otp_fields(&[("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET)]);

        assert!(e.set_otp(&settings("not base32 !!", None, None)).is_err());
        assert!(e
            .set_otp(&settings(TIME_OTP_TEST_SECRET, Some(90), None))
            .is_err());

        assert_eq!(
            value_of(&e, "TimeOtp-Secret-Base32").unwrap(),
            TIME_OTP_TEST_SECRET
        );
        assert!(e.current_otp_token_data("TimeOtp-Secret-Base32").is_some());
    }

    #[test]
    fn removing_a_2fa_leaves_no_keepass_field_behind() {
        let mut e = entry_with_otp_fields(&[
            ("TimeOtp-Secret-Base32", TIME_OTP_TEST_SECRET),
            (
                "TimeOtp-Secret-Hex",
                "3132333435363738393031323334353637383930",
            ),
            ("TimeOtp-Period", "60"),
            ("TimeOtp-Length", "8"),
            ("TimeOtp-Algorithm", "HMAC-SHA-256"),
        ]);

        e.remove_otp();

        for field in [
            "TimeOtp-Secret-Base32",
            "TimeOtp-Secret-Hex",
            "TimeOtp-Period",
            "TimeOtp-Length",
            "TimeOtp-Algorithm",
        ] {
            assert!(value_of(&e, field).is_none(), "{} is left behind", field);
        }
        assert!(e.parsed_otp_values.is_none());
    }

    // otp is not a field of the preset: an emptied one would stay in the form as an empty custom field
    #[test]
    fn removing_a_2fa_drops_the_otp_field() {
        let mut e = entry_with_otp_fields(&[("otp", &otp_url(TIME_OTP_TEST_SECRET))]);

        e.remove_otp();

        assert!(value_of(&e, "otp").is_none());
        assert!(e.parsed_otp_values.is_none());
    }
}

/*
fn parse_all_otp_fields(&mut self) {
        let otp_vals: HashMap<String, ParsedOtpData> = self
            .entry_field
            .get_key_values()
            .into_iter()
            .filter_map(|k| {
                if k.value.starts_with(OTP_URL_PREFIX) {
                    let parsed_otp_data = match OtpData::from_url(&k.value) {
                        Ok(pd) => ParsedOtpData::Success(pd),
                        Err(e) => ParsedOtpData::Failure(format!(
                            "OtpUrl Parsing Failed with error {}",
                            e
                        )),
                    };
                    Some((k.key.clone(), parsed_otp_data))
                } else {
                    None
                }
            })
            .collect();

        if !otp_vals.is_empty() {
            self.parsed_otp_values = Some(otp_vals);
        }
    }

    pub fn current_otp(&self, otp_field_name: &str) -> ParsedOtpData {
        match self
            .parsed_otp_values
            .as_ref()
            .map(|m| m.get(otp_field_name))
            .flatten()
            .map(|pd| pd)
        {
            Some(otp_data) => otp_data.clone(),
            None => ParsedOtpData::Failure("No parsed otp data is found".into()),
        }
    }

*/

// History limits (HistoryMaxItems / HistoryMaxSize) applied the way KeePass does it
// (KeePassLib PwEntry.MaintainBackups / GetSize)
#[cfg(test)]
mod history_limit_tests {
    use super::{AutoType, BinaryKeyValue, Entry, KeyValue};
    use crate::db_content::entry::Association;
    use crate::db_content::{CustomData, Item};
    use chrono::{Duration, NaiveDate};

    fn at(minute: i64) -> chrono::NaiveDateTime {
        NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            + Duration::minutes(minute)
    }

    // A history version modified at the given minute, optionally with an attachment of that size
    fn version(minute: i64, attachment_size: usize) -> Entry {
        let mut e = Entry::new();
        e.times.last_modification_time = at(minute);
        if attachment_size > 0 {
            e.binary_key_values.push(BinaryKeyValue {
                key: "a.bin".into(),
                value: String::default(),
                index_ref: 0,
                data_hash: minute as u64,
                data_size: attachment_size,
            });
        }
        e
    }

    fn entry_with_history(versions: Vec<Entry>, max_items: i32, max_size: i64) -> Entry {
        let mut e = version(1000, 0);
        e.history.entries = versions;
        e.meta_share.set_history_max_items(max_items);
        e.meta_share.set_history_max_size(max_size);
        e
    }

    fn minutes(histories: &[Entry]) -> Vec<i64> {
        histories
            .iter()
            .map(|h| (h.times.last_modification_time - at(0)).num_minutes())
            .collect()
    }

    // KeePass: HistoryMaxItems = 0 means no history at all (we used to keep one version)
    #[test]
    fn zero_max_items_keeps_no_history() {
        let mut e = entry_with_history(vec![version(10, 0), version(20, 0)], 0, -1);
        assert!(e.create_histories().is_empty());
    }

    #[test]
    fn unlimited_limits_keep_every_version() {
        let versions = (0..15).map(|m| version(m, 0)).collect();
        let mut e = entry_with_history(versions, -1, -1);
        assert_eq!(e.create_histories().len(), 16);
    }

    // KeePass removes the version with the oldest LastModificationTime, not the first in the list
    // (after a merge the list is not in time order)
    #[test]
    fn max_items_removes_oldest_by_modification_time() {
        let versions = vec![version(30, 0), version(10, 0), version(20, 0)];
        let mut e = entry_with_history(versions, 2, -1);
        assert_eq!(minutes(&e.create_histories()), vec![30, 1000]);
    }

    #[test]
    fn max_size_removes_oldest_until_history_fits() {
        let versions = vec![
            version(10, 10_000),
            version(20, 10_000),
            version(30, 10_000),
        ];
        // ~31 KB of history (3 attachments + the new version) against a 25 KB limit
        let mut e = entry_with_history(versions, -1, 25_000);
        assert_eq!(minutes(&e.create_histories()), vec![20, 30, 1000]);
    }

    #[test]
    fn max_items_is_applied_before_max_size() {
        let versions = vec![version(10, 0), version(20, 10_000), version(30, 0)];
        let mut e = entry_with_history(versions, 2, 5_000);
        // items: keep 30 and the new version (20 with the attachment is dropped by count already)
        assert_eq!(minutes(&e.create_histories()), vec![30, 1000]);
    }

    // Same number KeePass' PwEntry.GetSize gives for this entry: 2 bytes per UTF-16 char plus
    // fixed per-item overheads
    #[test]
    fn keepass_size_matches_the_keepass_formula() {
        let mut e = Entry::new();
        for (k, v) in [("Title", "Bank"), ("Password", "pässwörd")] {
            e.entry_field.insert_key_value(KeyValue {
                key: k.into(),
                value: v.into(),
                protected: false,
            });
        }
        e.binary_key_values.push(BinaryKeyValue {
            key: "f.txt".into(),
            value: String::default(),
            index_ref: 0,
            data_hash: 1,
            data_size: 100,
        });
        e.auto_type = AutoType {
            enabled: true,
            default_sequence: Some("{USERNAME}".into()),
            associations: vec![Association {
                window: "Win".into(),
                key_stroke_sequence: Some("{PASSWORD}".into()),
            }],
            data_transfer_obfuscation: 0,
        };
        e.override_url = "cmd://x".into();
        e.tags = "a;bb".into();
        e.custom_data = CustomData::default();
        e.custom_data.insert_item(Item::from_kv("k", "vv"));

        // bytes: 276 + 2 fields * 40 + 1 attachment * 65 + 100 + 1 association * 24 + 2 tags * 8 + 1 item * 16
        let bytes = 276 + 2 * 40 + 65 + 100 + 24 + 2 * 8 + 16;
        // chars: Title+Bank, Password+pässwörd (8 UTF-16 units, 10 UTF-8 bytes), f.txt,
        // {USERNAME}, Win+{PASSWORD}, cmd://x, a+bb, k+vv
        let chars = (5 + 4) + (8 + 8) + 5 + 10 + (3 + 10) + 7 + (1 + 2) + (1 + 2);
        assert_eq!(e.keepass_size(), bytes + chars * 2);
    }

    // The entry form does not carry colors, OverrideURL, QualityCheck, PreviousParentGroup and the
    // auto-type obfuscation: updating from the form keeps them, the history copy has them too
    // The core no longer rewrites the CustomData of an entry (Step 43): a OneKeePass entry type in
    // it - and anything else there - stays as read, on the entry and on the copy put into history
    #[test]
    fn an_update_keeps_custom_data_as_read() {
        let mut entry = version(1, 0);
        entry.history.entries.clear();
        entry
            .custom_data
            .insert_item(Item::from_kv("OKP_K4", "c29tZS10eXBl"));
        entry
            .custom_data
            .insert_item(Item::from_kv("KPXC_X", "foreign"));
        let before = entry.custom_data.clone();

        let mut updated = entry.clone();
        updated.custom_data = CustomData::default();
        entry.update(updated);

        assert_eq!(entry.custom_data, before);
        assert_eq!(entry.history.entries.len(), 1);
        assert_eq!(entry.history.entries[0].custom_data, before);
    }

    #[test]
    fn form_update_keeps_keepass_properties() {
        let mut e = Entry::new();
        e.foreground_color = "#112233".into();
        e.background_color = "#445566".into();
        e.override_url = "cmd://firefox {URL}".into();
        e.quality_check = false;
        e.previous_parent_group = uuid::Uuid::new_v4();
        e.auto_type.data_transfer_obfuscation = 1;
        let before = e.clone();

        let from_form = Entry::new();
        e.update(from_form);

        for (actual, stage) in [(&e, "entry"), (&e.history.entries[0], "history")] {
            assert_eq!(
                actual.foreground_color, before.foreground_color,
                "{}",
                stage
            );
            assert_eq!(
                actual.background_color, before.background_color,
                "{}",
                stage
            );
            assert_eq!(actual.override_url, before.override_url, "{}", stage);
            assert_eq!(actual.quality_check, before.quality_check, "{}", stage);
            assert_eq!(
                actual.previous_parent_group, before.previous_parent_group,
                "{}",
                stage
            );
            assert_eq!(actual.auto_type.data_transfer_obfuscation, 1, "{}", stage);
        }
    }
}
