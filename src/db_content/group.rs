use crate::db_content::{CustomData, Times, UnknownElement};

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub(crate) uuid: Uuid,
    pub parent_group_uuid: Uuid,
    pub name: String,
    #[serde(default)]
    pub icon_id: i32,
    pub notes: String,
    pub tags: String,
    #[serde(default)]
    pub(crate) is_expanded: bool,
    #[serde(default = "Times::new")]
    pub(crate) times: Times,
    #[serde(skip)]
    pub custom_data: CustomData,
    // KeePass view state: the entry shown at the top of the list for this group
    #[serde(skip)]
    pub(crate) last_top_visible_entry: Uuid,
    // KDBX 4.1: the group this group was in before its last move (nil = none)
    #[serde(skip)]
    pub(crate) previous_parent_group: Uuid,
    pub(crate) marked_category: bool,

    pub(crate) default_auto_type_sequence: Option<String>,
    pub(crate) enable_auto_type: Option<bool>,
    // None = inherit from the parent group, as EnableAutoType
    #[serde(default)]
    pub(crate) enable_searching: Option<bool>,

    pub(crate) custom_icon_uuid: Option<Uuid>,

    // Elements of <Group> the core does not know - written back as read
    #[serde(skip)]
    pub(crate) unknown_elements: Vec<UnknownElement>,

    // Only the child group uuids are kept here and used to do lookup in 'root.all_groups'
    #[serde(default)]
    pub(crate) group_uuids: Vec<Uuid>,
    // Only the child entry uuids are kept here and used to do lookup in 'root.all_entries'
    #[serde(default)]
    pub(crate) entry_uuids: Vec<Uuid>,
}

// Mainly used for testing or during the databse merging
impl Group {
    pub(crate) fn name(&self) -> &String {
        &self.name
    }

    pub(crate) fn set_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_string();
        self
    }

    pub(crate) fn _notes(&self) -> &String {
        &self.notes
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn set_notes(&mut self, notes: &str) -> &mut Self {
        self.notes = notes.to_string();
        self
    }

    #[allow(unused)]
    #[inline]
    pub(crate) fn set_icon_id(&mut self, icon_id: i32) -> &mut Self {
        self.icon_id = icon_id;
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

    // Merge: a newer source group brings all its KeePass properties (PwGroup.AssignProperties),
    // not only the ones the group form edits (see Root::update_group)
    pub(crate) fn assign_merge_properties(&mut self, other: &Group) {
        self.is_expanded = other.is_expanded;
        self.default_auto_type_sequence = other.default_auto_type_sequence.clone();
        self.enable_auto_type = other.enable_auto_type;
        self.enable_searching = other.enable_searching;
        self.last_top_visible_entry = other.last_top_visible_entry;
        self.previous_parent_group = other.previous_parent_group;
        self.unknown_elements = other.unknown_elements.clone();
    }

    pub(crate) fn clear_children(&mut self) -> &mut Self {
        self.entry_uuids = vec![];
        self.group_uuids = vec![];
        self
    }
}

impl Group {
    // Creates a new group without uuid - a blank template filled in by the caller (uuid, parent).
    // Crate-only on purpose: with a nil uuid it is not a valid group, so no Default either;
    // outside the crate use new_with_id / with_parent
    pub(crate) fn new() -> Self {
        Group {
            uuid: Uuid::default(),
            parent_group_uuid: Uuid::default(),
            name: String::default(),
            icon_id: 48, //i32::default(), folder icon
            tags: String::default(),
            notes: String::default(),
            // KeePass default (PwGroup): a group without <IsExpanded> is expanded
            is_expanded: true,
            times: Times::new(),
            custom_data: CustomData::default(),
            custom_icon_uuid: None,
            last_top_visible_entry: Uuid::default(),
            previous_parent_group: Uuid::default(),
            marked_category: true,

            // Not sure these are used by keepass at all and it looks like mostly used whatever set in entries
            // None means inherit from parent settings for all entries
            // False if auto type is disabled for entries for this group
            // True if auto type is enabled for entries for this group
            enable_auto_type: None,
            enable_searching: None,
            default_auto_type_sequence: None,
            unknown_elements: vec![],

            group_uuids: vec![],
            entry_uuids: vec![],
        }
    }

    // Creates a new group with uuid set
    pub fn new_with_id() -> Self {
        let mut g = Group::new();
        g.uuid = Uuid::new_v4();
        g
    }

    pub fn with_parent(group_uuid: &Uuid) -> Self {
        let mut g = Group::new_with_id();
        g.parent_group_uuid = *group_uuid;
        g
    }

    pub(crate) fn get_uuid(&self) -> Uuid {
        self.uuid
    }

    pub(crate) fn parent_group_uuid(&self) -> Uuid {
        self.parent_group_uuid
    }

    pub(crate) fn set_parent_group_uuid(&mut self, group_uuid: &Uuid) -> &mut Self {
        self.parent_group_uuid = *group_uuid;
        self
    }

    pub fn sub_group_uuids(&self) -> &Vec<Uuid> {
        &self.group_uuids
    }

    pub fn entry_uuids(&self) -> &Vec<Uuid> {
        &self.entry_uuids
    }

    pub fn custom_data_to_group(&mut self) {
        self.marked_category = self.custom_data.is_category();
    }

    // pub fn group_to_custom_data(&mut self) {
    //     if self.marked_category {
    //         // Update the mark category custom data only if is not already set
    //         // to maintain the proper last_modification_time of this custom data
    //         if !self.custom_data.is_category() {
    //             self.custom_data.mark_as_category();
    //         }
    //     } else {
    //         // Remove any previous setting when marked_category is false
    //         self.custom_data.remove_category_marking();
    //     }
    // }

    // Called to set the group's custom data field values
    pub fn group_to_custom_data(&mut self) {
        if self.marked_category {
            // Remove any previous setting when marked_category is true
            self.custom_data.remove_category_marking();
        } else {
            // Update the mark category custom data only if is not already set
            // to maintain the proper last_modification_time of this custom data
            if self.custom_data.is_category() {
                self.custom_data.unmark_as_category();
            }
        }
    }

    pub fn mark_as_category(&mut self) {
        self.marked_category = true;
    }

    pub fn is_in_category(&self) -> bool {
        self.marked_category
    }

    pub fn visitor_action(&mut self) {
        println!("name is {}", self.name);
    }
}

#[cfg(test)]
mod tests {
    use super::Group;
    use uuid::Uuid;

    #[test]
    fn group_new_has_default_uuid() {
        let g = Group::new();
        assert_eq!(g.uuid, Uuid::default());
    }

    #[test]
    fn group_new_has_folder_icon() {
        let g = Group::new();
        assert_eq!(g.icon_id, 48);
    }

    #[test]
    fn group_new_marked_category_true() {
        let g = Group::new();
        assert!(g.marked_category);
    }

    #[test]
    fn group_new_with_id_has_non_default_uuid() {
        let g = Group::new_with_id();
        assert_ne!(g.uuid, Uuid::default());
    }

    #[test]
    fn group_new_with_id_uuids_are_unique() {
        let g1 = Group::new_with_id();
        let g2 = Group::new_with_id();
        assert_ne!(g1.uuid, g2.uuid);
    }

    #[test]
    fn group_with_parent_sets_parent_uuid() {
        let parent_id = Uuid::new_v4();
        let g = Group::with_parent(&parent_id);
        assert_eq!(g.parent_group_uuid, parent_id);
        assert_ne!(g.uuid, Uuid::default());
    }

    #[test]
    fn group_set_name_updates_name() {
        let mut g = Group::new_with_id();
        g.set_name("Passwords");
        assert_eq!(g.name(), "Passwords");
    }

    #[test]
    fn group_set_notes_updates_notes() {
        let mut g = Group::new_with_id();
        g.set_notes("My group notes");
        assert_eq!(g._notes(), "My group notes");
    }

    #[test]
    fn group_clear_children_empties_lists() {
        let mut g = Group::new_with_id();
        g.entry_uuids.push(Uuid::new_v4());
        g.group_uuids.push(Uuid::new_v4());
        g.clear_children();
        assert!(g.entry_uuids().is_empty());
        assert!(g.sub_group_uuids().is_empty());
    }

    #[test]
    fn group_mark_as_category() {
        let mut g = Group::new_with_id();
        g.marked_category = false;
        g.mark_as_category();
        assert!(g.is_in_category());
    }

    #[test]
    fn group_set_parent_group_uuid() {
        let mut g = Group::new_with_id();
        let parent_id = Uuid::new_v4();
        g.set_parent_group_uuid(&parent_id);
        assert_eq!(g.parent_group_uuid(), parent_id);
    }

    #[test]
    fn group_get_uuid_returns_correct_uuid() {
        let g = Group::new_with_id();
        assert_eq!(g.get_uuid(), g.uuid);
    }

    #[test]
    fn group_new_has_empty_children() {
        let g = Group::new();
        assert!(g.entry_uuids().is_empty());
        assert!(g.sub_group_uuids().is_empty());
    }
}

// Category flag <-> custom data marker OKP_GROUP_AS_CATEGORY ("OKP_K2"): a group is a category unless
// the marker says "No" (groups from other clients have no marker and are categories by design)
#[cfg(test)]
mod category_marker_tests {
    use super::Group;
    use crate::constants::custom_data_key::OKP_GROUP_AS_CATEGORY;

    // Saving writes the flag into custom data, loading reads it back
    fn save_and_load(g: &mut Group) {
        g.group_to_custom_data();
        g.custom_data_to_group();
    }

    #[test]
    fn unmarked_category_survives_save_and_load() {
        let mut g = Group::new_with_id();
        g.marked_category = false;
        save_and_load(&mut g);
        assert!(
            !g.is_in_category(),
            "unmarked group came back as a category"
        );
    }

    #[test]
    fn marked_category_survives_save_and_load_without_a_marker() {
        let mut g = Group::new_with_id();
        g.marked_category = true;
        save_and_load(&mut g);
        assert!(g.is_in_category());
        assert!(g.custom_data.get_item(OKP_GROUP_AS_CATEGORY).is_none());
    }

    // A group read from a KeePassXC / KeePassDX file has no marker
    #[test]
    fn group_without_marker_is_a_category() {
        let mut g = Group::new_with_id();
        g.marked_category = false;
        g.custom_data_to_group();
        assert!(g.is_in_category());
    }

    // The marker is written only when missing, so its modification time is kept across saves
    #[test]
    fn existing_no_marker_is_not_rewritten_on_save() {
        let mut g = Group::new_with_id();
        g.marked_category = false;
        g.group_to_custom_data();
        let first = g
            .custom_data
            .get_item(OKP_GROUP_AS_CATEGORY)
            .cloned()
            .unwrap();
        g.custom_data_to_group();
        g.group_to_custom_data();
        let second = g
            .custom_data
            .get_item(OKP_GROUP_AS_CATEGORY)
            .cloned()
            .unwrap();
        assert_eq!(second.value, "No");
        assert_eq!(first.last_modification_time, second.last_modification_time);
    }

    fn keepass_props(g: &mut Group) {
        g.is_expanded = false;
        g.default_auto_type_sequence = Some("{USERNAME}{ENTER}".into());
        g.enable_auto_type = Some(false);
        g.enable_searching = Some(false);
        g.last_top_visible_entry = uuid::Uuid::new_v4();
        g.previous_parent_group = uuid::Uuid::new_v4();
    }

    fn assert_keepass_props(actual: &Group, expected: &Group) {
        assert_eq!(actual.is_expanded, expected.is_expanded);
        assert_eq!(
            actual.default_auto_type_sequence,
            expected.default_auto_type_sequence
        );
        assert_eq!(actual.enable_auto_type, expected.enable_auto_type);
        assert_eq!(actual.enable_searching, expected.enable_searching);
        assert_eq!(
            actual.last_top_visible_entry,
            expected.last_top_visible_entry
        );
        assert_eq!(actual.previous_parent_group, expected.previous_parent_group);
    }

    // The group form carries only name / notes / tags / icons: saving it keeps the other
    // KeePass properties of the group
    #[test]
    fn form_update_keeps_keepass_properties() {
        let mut stored = Group::new_with_id();
        keepass_props(&mut stored);
        let mut root = crate::db_content::Root::new();
        root.insert_to_all_groups(stored.clone());

        let mut from_form = Group::new();
        from_form.uuid = stored.uuid;
        from_form.name = "Renamed".into();
        root.update_group(from_form, false);

        let updated = root.group_by_id(&stored.uuid).unwrap();
        assert_eq!(updated.name, "Renamed");
        assert_keepass_props(updated, &stored);
    }

    // Merge with a newer source group takes all its KeePass properties (PwGroup.AssignProperties)
    #[test]
    fn merge_update_takes_keepass_properties() {
        let stored = Group::new_with_id();
        let mut root = crate::db_content::Root::new();
        root.insert_to_all_groups(stored.clone());

        let mut source = stored.clone();
        keepass_props(&mut source);
        root.update_group(source.clone(), true);

        assert_keepass_props(root.group_by_id(&stored.uuid).unwrap(), &source);
    }

    // KeePass default: a group without <IsExpanded> is expanded
    #[test]
    fn group_new_is_expanded() {
        assert!(Group::new().is_expanded);
    }
}
