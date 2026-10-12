use crate::constants::entry_keyvalue_key::{PASSWORD, SERVICE, URL, USER_NAME};

// The standard preset: the fields every entry is shown with, besides the title and the notes that
// every kdbx entry has. The order is the order of the form - title, these fields, notes, then the
// entry's own fields.
//
// The preset lives in the code only and nothing of it is written to the file: an entry of the
// preset is a plain kdbx entry with these strings, so other programs see every field. UserName,
// Password and URL are kdbx standard keys; Service is ours and is a custom string for them
pub struct PresetField {
    pub key: &'static str,
    // Protected in the file (in memory and in the inner stream), as KeePass protects the password
    pub protected: bool,
}

pub const STANDARD_PRESET_FIELDS: &[PresetField] = &[
    PresetField {
        key: USER_NAME,
        protected: false,
    },
    PresetField {
        key: PASSWORD,
        protected: true,
    },
    PresetField {
        key: SERVICE,
        protected: false,
    },
    PresetField {
        key: URL,
        protected: false,
    },
];
