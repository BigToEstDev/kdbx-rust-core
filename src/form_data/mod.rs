mod categories;
mod db_setting;
mod entry;
pub(crate) mod parsing;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{db::KdbxFile, db_content::Meta};

pub use self::categories::*;
pub use self::entry::*;

pub use self::db_setting::*;

// The following way can be used in case we want to export types from 'entry' under some
// other module name.
// The calleer can use the following
// pub use crate::form_data::entry_form_data::{EntryFormData, EntrySummary, EntryTypeNames};
// pub mod entry_form_data {
//     pub use super::entry::*;
// }

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MetaFormData {
    pub(crate) database_name: String,
    pub(crate) database_description: String,
    // -1 = no limit for both
    pub(crate) history_max_items: i32,
    // Bytes (KeePass shows it in MB)
    pub(crate) history_max_size: i64,
}

impl From<&Meta> for MetaFormData {
    fn from(meta: &Meta) -> Self {
        Self {
            database_name: meta.database_name.clone(),
            database_description: meta.database_description.clone(),
            history_max_items: meta.meta_share.history_max_items(),
            history_max_size: meta.meta_share.history_max_size(),
        }
    }
}

// Only the form fields are set; the result is passed to Meta::update, which copies just these
impl From<&MetaFormData> for Meta {
    fn from(form_data: &MetaFormData) -> Self {
        let mut meta = Meta::new();

        meta.database_name = form_data.database_name.clone();
        meta.database_description = form_data.database_description.clone();
        meta.meta_share
            .set_history_max_items(form_data.history_max_items);
        meta.meta_share
            .set_history_max_size(form_data.history_max_size);

        meta
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct KdbxLoaded {
    // Full database uri
    pub db_key: String,
    // Just the database name
    pub database_name: String,
    // The file name part of full database uri
    pub file_name: Option<String>,
    // Full key file uri
    pub key_file_name: Option<String>,
}

// See write_new_db_kdbx_file fn

// As this conversion is called only for desktop csv loading for now, the mobil clause is not called
// When we introduce, csv import in mobile, then we need to ensure that 'file_name' part is set for mobile properly
// Instead of using From based kdbx_file.into for mobile, we can add a constructor method  KdbxLoaded::from(kdbx_file: &KdbxFile,file_name)
impl From<&KdbxFile> for KdbxLoaded {
    fn from(kdbx_file: &KdbxFile) -> Self {
        let db_key = kdbx_file.get_database_file_name().into();
        let database_name = kdbx_file.get_database_name().into();

        let (file_name, key_file_name);

        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "macos",target_os = "windows",target_os = "linux"))] {
                (file_name,key_file_name) = (crate::util::file_name(kdbx_file.get_database_file_name()),kdbx_file.get_key_file_name());
            } else {
                // In case of Mobile. Needs fixing to set 'file_name'

                (file_name,key_file_name) = (None, kdbx_file.get_key_file_name()) ;
            }
        }

        KdbxLoaded {
            db_key,
            database_name,
            file_name,
            key_file_name,
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct KdbxSaved {
    pub db_key: String,
    // This is the database name from the meta data of kdbx content
    pub database_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupSummary {
    pub uuid: Uuid,
    pub parent_group_uuid: Uuid,
    pub name: String,
    pub icon_id: i32,
    pub custom_icon_uuid: Option<String>,
    pub group_uuids: Vec<String>,
    pub entry_uuids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::MetaFormData;
    use crate::db_content::Meta;

    fn form(meta: &Meta) -> MetaFormData {
        MetaFormData::from(meta)
    }

    // The settings form carries only name, description and the two history limits. Saving it must not
    // reset Meta fields the form does not have - they come from the file (KeePass, KeePassXC)
    #[test]
    fn update_from_settings_form_keeps_fields_not_in_the_form() {
        let mut meta = Meta::new();
        meta.recycle_bin_enabled = true;
        meta.maintenance_history_days = 30;

        let mut settings = form(&meta);
        settings.database_name = "Renamed".into();
        meta.update((&settings).into()).unwrap();

        assert_eq!(meta.database_name, "Renamed");
        assert!(
            meta.recycle_bin_enabled,
            "RecycleBinEnabled reset by the settings form"
        );
        assert_eq!(
            meta.maintenance_history_days, 30,
            "MaintenanceHistoryDays reset"
        );
    }

    // Entries read the limits through the shared MetaShare, so update must write into self.meta_share
    #[test]
    fn update_from_settings_form_sets_both_history_limits_in_shared_meta() {
        let mut meta = Meta::new();
        let shared = std::sync::Arc::clone(&meta.meta_share);

        let mut settings = form(&meta);
        settings.history_max_items = 3;
        settings.history_max_size = 4096_i64 * 1024 * 1024;
        meta.update((&settings).into()).unwrap();

        assert_eq!(shared.history_max_items(), 3);
        assert_eq!(shared.history_max_size(), 4096_i64 * 1024 * 1024);
    }
}
