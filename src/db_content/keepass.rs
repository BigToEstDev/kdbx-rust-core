use std::collections::HashMap;
use uuid::Uuid;

use crate::db_content::{AttachmentHashValue, Entry, Meta, Root, UnknownElements};

use crate::error::{self, Result};
use crate::util;

use super::EntryType;

#[derive(Debug, Clone)]
pub(crate) struct KeepassFile {
    pub(crate) meta: Meta,
    pub(crate) root: Root,

    // Unknown elements read directly under <KeePassFile> (see db_content/unknown_element.rs)
    pub(crate) unknown_elements: UnknownElements,
}

impl KeepassFile {
    // Applies this database's history limits to every entry (KeePass PwDatabase.MaintainBackups).
    // Called after the limits change in the db settings and at the end of a merge
    pub(crate) fn maintain_all_histories(&mut self) -> bool {
        let max_items = self.meta.meta_share.history_max_items();
        let max_size = self.meta.meta_share.history_max_size();
        self.root.maintain_all_histories(max_items, max_size)
    }

    pub(crate) fn new() -> KeepassFile {
        KeepassFile {
            meta: Meta::new(),
            root: Root::new(),
            unknown_elements: UnknownElements::default(),
        }
    }

    pub(crate) fn empty_trash(&mut self) -> Result<()> {
        // The recycle_bin_uuid from the root itself used for now till we move the root 'recycle_bin_uuid'
        // to meta 'recycle_bin_uuid' instead of using share_meta_to_root and share_root_to_meta
        self.root.empty_trash(self.root.recycle_bin_uuid())
    }

    // TODO:
    // Instead of this way of copying recycle_bin_uuid etc to 'root' and back, all methods in 'root' that
    // depend on 'meta' fields should be implemented in 'meta' and then call 'root' method
    // with that data. For example,  'get_all_entries' and other move to recycle methods in 'root'
    // should accept the relevant meta field and then use.

    // See 'empty_trash' method for additional comments

    // TODO: For now we are just delegating to 'root' and need to pass excluded group ids (recycle group id and template group id )
    pub(crate) fn get_all_entries(&self, exclude: bool) -> Vec<&Entry> {
        self.root.get_all_entries(exclude)
    }

    // Collects all entries that are not in recycle bin
    pub(crate) fn collect_all_active_entries(&self) -> Vec<&Entry> {
        self.root
            .collect_all_active_entries(self.root.recycle_bin_uuid())
    }

    pub(crate) fn collect_favorite_entries(&self) -> Vec<&Entry> {
        self.root
            .collect_favorite_entries(self.root.recycle_bin_uuid())
    }

    pub(crate) fn deleted_group_uuids(&self) -> Vec<Uuid> {
        // TODO: Pass recycle bin group uuid from meta to root
        self.root.deleted_group_uuids()
    }

    // pub fn delete_custom_entry_type(&mut self, entry_type_name: &str) -> Result<()> {
    //     if self.root.custom_entry_type_entries(entry_type_name).len() != 0 {
    //         //error::Error::DataError("Entry type can not be deleted as some entries are of this type")
    //         return Err(error::Error::CustomEntryTypeInUse);
    //     }
    //     else {
    //         return Ok(self.meta.delete_custom_entry_type(entry_type_name));
    //     }
    // }

    pub(crate) fn delete_custom_entry_type_by_id(
        &mut self,
        entry_type_uuid: &Uuid,
    ) -> Result<Option<EntryType>> {
        if !self
            .root
            .custom_entry_type_entries_by_id(entry_type_uuid)
            .is_empty()
        {
            //error::Error::DataError("Entry type can not be deleted as some entries are of this type")
            Err(error::Error::CustomEntryTypeInUse)
        } else {
            Ok(self.meta.delete_custom_entry_type_by_id(entry_type_uuid))
        }
    }

    // Ensures that the meta share for the newly created entry is initialized properly
    pub(crate) fn insert_entry(&mut self, mut entry: Entry) -> Result<()> {
        entry.meta_share = self.meta.clone_meta_share();
        self.root.insert_entry(entry)
    }

    // Memory-security lock: volatile-zero the sensitive in-memory content
    // (entry field values, incl. history) before this KeepassFile is dropped on
    // lock. Rust does not zero on drop, so without this the plaintext would linger
    // in freed heap. Best-effort: wipes the primary resident copy; transient copies
    // made earlier by normal operations are not tracked. (Meta is not scrubbed -
    // it holds no entry secrets.)
    pub(crate) fn zeroize_sensitive_content(&mut self) {
        self.root.zeroize_sensitive_content();
    }

    // Called after reading xml content
    pub(crate) fn after_xml_reading(
        &mut self,
        attachment_hash_indexed: &HashMap<i32, (AttachmentHashValue, usize)>,
        #[cfg(any(feature = "desktop-ssh-agent", rust_analyzer))]
        attachment_content: &dyn Fn(&AttachmentHashValue) -> Option<Vec<u8>>,
    ) {
        // Need to read any meta specific custom data first
        self.meta.copy_from_custom_data();

        // IMPORTANT:We need to set attachment hashes in all entries read from xml
        self.root.set_attachment_hashes(attachment_hash_indexed);

        // The uuid of a group that is identified as recycle group and this is available only as child
        // element of Meta element
        if self.meta.recycle_bin_uuid != Uuid::default() {
            self.root.set_recycle_bin_uuid(self.meta.recycle_bin_uuid);
        }

        // This sets any relavant fields in the group based on the custom data
        self.root.custom_data_to_groups();

        //self.root.custom_data_to_entries();
        self.root.entries_after_xml_reading(&self.meta);

        #[cfg(any(feature = "desktop-ssh-agent", rust_analyzer))]
        self.root
            .adjust_imported_ssh_key_attachment_entries(&self.meta, attachment_content);
    }

    // Called before writing xml content
    pub(crate) fn before_xml_writing(
        &mut self,
        hash_index_ref: &HashMap<AttachmentHashValue, i32>,
    ) {
        self.meta.copy_to_custom_data();

        // Need to set the new index_refs of all attachments after writing the binaries
        self.root.set_attachment_index_refs(hash_index_ref);

        // Any entries related one
        self.root.entries_before_xml_writing();

        // When a recycle group is created under root group (on delete or on merge), we need to set it
        // in Meta so that it can be written as child element of Meta and subsequent reading of db
        // includes this special group uuid.
        // RecycleBinEnabled is switched on only then: a bin read from the file keeps the flag it has
        // there - a user may have disabled the recycle bin in KeePass and kept the group
        let bin_uuid = self.root.recycle_bin_uuid();
        if bin_uuid != Uuid::default() && bin_uuid != self.meta.recycle_bin_uuid {
            self.meta.recycle_bin_uuid = bin_uuid;
            self.meta.recycle_bin_enabled = true;
            self.meta.recycle_bin_changed = util::now_utc();
        }

        // This copies any custom data specific field information back to custom data before xml writing
        self.root.groups_to_custom_data();

        // Sets the new version
        //self.meta.custom_data.set_internal_version(&INTERNAL_VERSION.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Recycle bin created by the core (on the first delete) switches the bin on
    #[test]
    fn recycle_bin_created_by_core_is_enabled() {
        let mut kp = KeepassFile::new();
        kp.root.recycle_bin_group();
        let changed_before = kp.meta.recycle_bin_changed;

        kp.before_xml_writing(&HashMap::new());

        assert_ne!(kp.meta.recycle_bin_uuid, Uuid::default());
        assert_eq!(kp.meta.recycle_bin_uuid, kp.root.recycle_bin_uuid());
        assert!(kp.meta.recycle_bin_enabled);
        assert!(kp.meta.recycle_bin_changed >= changed_before);
    }

    // Recycle bin read from the file keeps the flag it has there (disabled in KeePass)
    #[test]
    fn recycle_bin_from_file_keeps_disabled_flag() {
        let mut kp = KeepassFile::new();
        let bin_uuid = Uuid::new_v4();
        kp.meta.recycle_bin_uuid = bin_uuid;
        kp.meta.recycle_bin_enabled = false;
        kp.root.set_recycle_bin_uuid(bin_uuid);

        kp.before_xml_writing(&HashMap::new());

        assert!(
            !kp.meta.recycle_bin_enabled,
            "RecycleBinEnabled switched on by save"
        );
        assert_eq!(kp.meta.recycle_bin_uuid, bin_uuid);
    }
}
