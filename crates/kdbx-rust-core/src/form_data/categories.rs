use crate::db_content::{split_tags, Entry, KeepassFile};

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::GroupSummary;

#[derive(Serialize, Deserialize, Debug)]
pub struct GroupTree {
    //pub root_uuid: String,
    pub root_uuid: Uuid,
    pub recycle_bin_uuid: Uuid,
    pub deleted_group_uuids: Vec<Uuid>,
    pub groups: HashMap<String, GroupSummary>,
}

// TODO:
// We need to fix the use of '#[serde(rename_all = "camelCase")]' and change it to use serde attribute
// tag and content as shown below
// Changes to be done for both Desktop and Mobile same time if we change this in enum EntryCategory
// See in entry-summary-data fn of background.cljs

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryCategory {
    AllEntries,
    Favorites,
    Deleted,
    // Deserilaizes as {"group","someuuid"} - in cljs {:group "someuuid"}
    Group(String),
    Tag(String),
}

// TODO: See the above comments
/*
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type_name", content = "content")]
pub enum EntryCategory {
    AllEntries,
    Favorites,
    Deleted,
    Group(String),
    Tag(String),
}
*/

// Called to get all entries for any given entry category
pub(crate) fn entry_by_category<'a>(
    kp: &'a KeepassFile,
    entry_category: &'a EntryCategory,
) -> Vec<&'a Entry> {
    let mut entries: Vec<&Entry> = vec![];
    match entry_category {
        EntryCategory::AllEntries => kp.collect_all_active_entries(),
        EntryCategory::Favorites => kp.collect_favorite_entries(),
        EntryCategory::Deleted => kp.root.deleted_entries(),
        EntryCategory::Group(uuid) => {
            if let Ok(group_uuid) = Uuid::parse_str(uuid) {
                if let Some(g) = kp.root.group_by_id(&group_uuid) {
                    for entry_uuid in &g.entry_uuids {
                        if let Some(e) = kp.root.entry_by_id(entry_uuid) {
                            entries.push(e);
                        }
                    }
                }
            }
            //All entries that are under this group
            entries
        }
        EntryCategory::Tag(name) => kp
            .collect_all_active_entries()
            .iter()
            .filter(|e| split_tags(&e.tags).contains(name))
            .copied()
            .collect::<Vec<_>>(),
    }
}
