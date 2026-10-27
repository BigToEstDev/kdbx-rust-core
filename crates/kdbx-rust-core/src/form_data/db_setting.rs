use serde::{Deserialize, Serialize};

use crate::db::{Compression, ContentCipherId, KdbxVersion, KdfAlgorithm};

use super::MetaFormData;

#[derive(Clone, Serialize, Deserialize)]
pub struct DbSettings {
    pub(crate) kdf: KdfAlgorithm,
    pub(crate) cipher_id: ContentCipherId,
    pub(crate) password: Option<String>,
    pub(crate) key_file_name: Option<String>,
    // Used for both reading and setting from UI side
    pub(crate) password_used: bool,
    pub(crate) key_file_used: bool,
    // Set when changed from the UI side
    pub(crate) password_changed: bool,
    pub(crate) key_file_changed: bool,

    // Just the file name component of the full key file name 'key_file_name'
    // Used in mobile mainly
    pub(crate) key_file_name_part: Option<String>,
    pub(crate) database_file_name: String,
    // Output only, as key_file_name: the version the file was read as, 4.1 once saved - the core writes no
    // other (Step 64)
    pub(crate) kdbx_version: KdbxVersion,
    // Both ways: how the content is packed from the next save on
    pub(crate) compression: Compression,
    pub(crate) meta: MetaFormData,
}

// Written by hand: the derived one would print the secret - see crate::redacted
impl std::fmt::Debug for DbSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbSettings")
            .field("kdf", &self.kdf)
            .field("cipher_id", &self.cipher_id)
            .field("password", &crate::redacted::redacted_opt(&self.password))
            .field("key_file_name", &self.key_file_name)
            .field("password_used", &self.password_used)
            .field("key_file_used", &self.key_file_used)
            .field("password_changed", &self.password_changed)
            .field("key_file_changed", &self.key_file_changed)
            .field("key_file_name_part", &self.key_file_name_part)
            .field("database_file_name", &self.database_file_name)
            .field("kdbx_version", &self.kdbx_version)
            .field("compression", &self.compression)
            .field("meta", &self.meta)
            .finish()
    }
}

// Used in integration test
// #[allow(unused)]
impl DbSettings {
    pub fn get_database_name(&self) -> &str {
        &self.meta.database_name
    }

    pub fn set_database_name(&mut self, name: &str) -> &mut Self {
        self.meta.database_name = name.into();
        self
    }

    /// The version of KDBX the file was read as; 4.1 once it is saved. Output only.
    pub fn kdbx_version(&self) -> KdbxVersion {
        self.kdbx_version
    }

    pub fn compression(&self) -> Compression {
        self.compression
    }

    pub fn set_compression(&mut self, compression: Compression) -> &mut Self {
        self.compression = compression;
        self
    }

    /// The name of the key file the database is closed with, to show - not a path to open. Output only:
    /// `set_db_settings` takes a new key file as content beside the settings and never reads this.
    pub fn key_file_name(&self) -> Option<&str> {
        self.key_file_name.as_deref()
    }
}

// Used in integration test
// #[allow(unused)]
// impl MetaFormData {
//     pub fn get_database_name(&self) -> &str {
//         &self.database_name
//     }

//     pub fn set_database_name(&mut self, name: &str) -> &mut Self {
//         self.database_name = name.into();
//         self
//     }
// }
