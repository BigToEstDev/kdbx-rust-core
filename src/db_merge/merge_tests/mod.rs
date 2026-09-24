mod common;
mod icon_merge;

use crate::{
    constants::entry_keyvalue_key::TITLE,
    db_content::{Group, UnknownElement},
    util,
};
use common::*;

use test_context::{test_context, TestContext};

use crate::db_merge::merger::Merger;

struct MergeTestContext {}

impl TestContext for MergeTestContext {
    fn setup() -> MergeTestContext {
        dummy_key_store_service::init();
        MergeTestContext {}
    }

    fn teardown(self) {
        // Perform any teardown you wish.
    }
}

#[test_context(MergeTestContext)]
#[test]
fn verify_new_group(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_mut().unwrap();

    let mut group1 = Group::with_parent(&source_db.root.root_uuid());
    group1.set_name("S_G1_db1");
    source_db.root.insert_group(group1).unwrap();

    let mut group1 = Group::with_parent(&target_db.root.root_uuid());
    group1.set_name("T_G1_db2");
    target_db.root.insert_group(group1).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let groups = target
        .keepass_main_content
        .as_ref()
        .unwrap()
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in final target db are {:?}", &groups);

    assert!(groups.contains(&"S_G1_db1".to_string()));
}

#[test_context(MergeTestContext)]
#[test]
fn verify_updated_group(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    util::test_clock::advance_by(1);

    if let Some(g1) = source_db.root.group_by_name_mut("group1") {
        g1.set_name("group1 changed").update_modification_time_now();
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let groups = target_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in final target db are {:?}", &groups);

    assert!(groups.contains(&"group1 changed".to_string()));
}

// Step 18: what the core does not show must travel with the object it belongs to. The
// newer source group and entry carry unknown elements - inside <Times> too - and the
// target has none of them; after the merge the target must carry them
#[test_context(MergeTestContext)]
#[test]
fn verify_unknown_elements_of_newer_source_are_merged_in(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    util::test_clock::advance_by(1);

    let group_uuid = {
        let g1 = source_db.root.group_by_name_mut("group1").unwrap();
        g1.unknown_elements
            .push(vec![], UnknownElement::new("XGroup".into(), vec![]));
        g1.unknown_elements.push(
            vec!["Times".to_string()],
            UnknownElement::new("XGroupTimes".into(), vec![]),
        );
        g1.update_modification_time_now();
        g1.get_uuid()
    };

    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();
    let entry_uuid = e1.get_uuid();
    source_db
        .root
        .entry_by_id_mut(&entry_uuid)
        .unwrap()
        .unknown_elements
        .push(
            vec!["Times".to_string()],
            UnknownElement::new("XEntryTimes".into(), vec![]),
        );

    // Правка записи идёт через форму и не несёт неизвестных элементов: Entry::update
    // намеренно оставляет их от прочитанного файла, иначе правка теряла бы чужие данные
    e1.entry_field.update_value(TITLE, "entry1 changed");
    source_db.root.update_entry(e1).unwrap();
    assert_eq!(
        source_db
            .root
            .entry_by_id(&entry_uuid)
            .unwrap()
            .unknown_elements
            .iter()
            .count(),
        1,
        "правка записи потеряла неизвестные элементы"
    );

    // В цели этих элементов нет - иначе тест прошёл бы и без переноса
    let target_db = target.keepass_main_content.as_ref().unwrap();
    assert!(target_db
        .root
        .group_by_id(&group_uuid)
        .unwrap()
        .unknown_elements
        .is_empty());
    assert!(target_db
        .root
        .entry_by_id(&entry_uuid)
        .unwrap()
        .unknown_elements
        .is_empty());

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();

    let merged_group: Vec<_> = target_db
        .root
        .group_by_id(&group_uuid)
        .unwrap()
        .unknown_elements
        .iter()
        .map(|(path, element)| (path.to_vec(), element.tag.clone()))
        .collect();
    assert_eq!(
        merged_group,
        vec![
            (vec![], "XGroup".to_string()),
            (vec!["Times".to_string()], "XGroupTimes".to_string())
        ],
        "неизвестные элементы группы не перенеслись при слиянии"
    );

    let merged_entry: Vec<_> = target_db
        .root
        .entry_by_id(&entry_uuid)
        .unwrap()
        .unknown_elements
        .iter()
        .map(|(path, element)| (path.to_vec(), element.tag.clone()))
        .collect();
    assert_eq!(
        merged_entry,
        vec![(vec!["Times".to_string()], "XEntryTimes".to_string())],
        "неизвестные элементы записи не перенеслись при слиянии"
    );
}

#[test_context(MergeTestContext)]
#[test]
fn verify_group_location_changed(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    // Create a new group
    let mut group3 = Group::with_parent(&source_db.root.root_uuid());
    group3.set_name("group3").update_modification_time_now();
    let g3_uuid = group3.get_uuid();
    source_db.root.insert_group(group3).unwrap();

    // Need to enusre that the following group move is happens in some later time
    util::test_clock::advance_by(1);

    // Move the group1 as child of group3 in the source
    let g1_uuid = source_db.root.group_by_name("group1").unwrap().get_uuid();

    source_db.root.move_group(g1_uuid, g3_uuid).unwrap();

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();

    let g1_parent_uuid = target_db
        .root
        .group_by_id(&g1_uuid)
        .unwrap()
        .parent_group_uuid();

    // println!("g3_uuid is {}, g1_parent is {}  ", g3_uuid, g1_parent);

    assert_eq!(g1_parent_uuid, g3_uuid);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_root_group_updated(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();

    util::test_clock::advance_by(1);

    let new_root_name = "root name changed";

    if let Some(g1) = source_db.root.group_by_id_mut(&source_db.root.root_uuid()) {
        g1.set_name(new_root_name).update_modification_time_now();
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let groups = target_db
        .root
        .get_all_groups(false)
        .iter()
        .map(|g| g.name.clone())
        .collect::<Vec<String>>();

    // println!("groups in final target db are {:?}", &groups);
    assert!(groups.contains(&new_root_name.to_string()));
}

#[test_context(MergeTestContext)]
#[test]
fn verify_entry_location_changed(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    // Need to enusre that the following entry move is happens in some later time
    util::test_clock::advance_by(1);

    // Move the entry to group2 as child in source db
    let g2 = source_db.root.group_by_name("group2").unwrap().clone();

    let g2_uuid = g2.get_uuid();

    // println!("-- Group {} and child entries BEFORE {:?}",&g2_uuid, g2.entry_uuids() ) ;

    let e1_uuid = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .get_uuid();

    // println!("-- entry 1 uuid is {}",&e1_uuid);

    source_db.root.move_entry(e1_uuid, g2_uuid).unwrap();

    // before merge target db's "group2" should have one entry
    let g2 = target_db.root.group_by_name("group2").unwrap().clone();

    //let g2_uuid = g2.get_uuid().clone();
    // println!("-- Group {} and child entries AFTER {:?}",&g2_uuid, g2.entry_uuids() ) ;

    assert!(g2.entry_uuids().len() == 1);

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let g2 = target_db.root.group_by_name("group2").unwrap().clone();

    // let g2_uuid = g2.get_uuid().clone();
    // println!("-- Group {} and child entries AFTER {:?}",&g2_uuid, g2.entry_uuids() ) ;

    assert!(g2.entry_uuids().len() == 2);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_entry_simple_update(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    let mut e1 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry1")
        .unwrap()
        .clone();

    let e1_uuid = e1.get_uuid();

    let before_histories = e1.histories().clone();
    // println!("before_histories {:?}", &before_histories.len());
    assert!(before_histories.is_empty());

    util::test_clock::advance_by(1);

    e1.entry_field.update_value(TITLE, "entry1 changed");
    source_db.root.update_entry(e1.clone()).unwrap();

    let e1 = target_db.root.entry_by_id(&e1_uuid).unwrap().clone();
    let target_entry_before_histories = e1.histories().clone();
    // println!("target target_entry_before_histories {:?}", &target_entry_before_histories.len());
    assert!(target_entry_before_histories.is_empty());

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let e1 = target_db.root.entry_by_id(&e1_uuid).unwrap().clone();
    let target_entry_after_histories = e1.histories().clone();
    // println!("target target_entry_after_histories {:?}", &target_entry_after_histories.len());
    assert!(target_entry_after_histories.len() == 1);
}

// KeePass trims the history of every entry to the target's limits at the end of MergeIn
// (PwDatabase.MaintainBackups); the merged union of both histories must not exceed them
#[test_context(MergeTestContext)]
#[test]
fn verify_merged_history_respects_target_limits(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let e1_uuid = {
        let source_db = source.keepass_main_content.as_mut().unwrap();
        let mut e1_uuid = None;
        for i in 1..=3 {
            util::test_clock::advance_by(1);
            let e = find_update_entry(
                source_db,
                if i == 1 { "entry1" } else { "src" },
                TITLE,
                "src",
            );
            e1_uuid = Some(e.get_uuid());
        }
        e1_uuid.unwrap()
    };
    {
        let target_db = target.keepass_main_content.as_mut().unwrap();
        for i in 1..=3 {
            util::test_clock::advance_by(1);
            find_update_entry(
                target_db,
                if i == 1 { "entry1" } else { "tgt" },
                TITLE,
                "tgt",
            );
        }
        target_db.meta.meta_share.set_history_max_items(4);
    }

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let histories = target_db
        .root
        .entry_by_id(&e1_uuid)
        .unwrap()
        .histories()
        .clone();
    assert!(
        histories.len() <= 4,
        "merged history has {} versions, the target limit is 4",
        histories.len()
    );
}

#[test_context(MergeTestContext)]
#[test]
fn verify_meta_add_custom_icon(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    let dummy_icon_data: Vec<u8> = vec![1, 2, 55, 67];
    source_db.meta.add_custom_icon(&dummy_icon_data);

    assert!(target_db.meta.all_custom_icons().is_empty());

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    assert!(target.keepass_main_content().meta.all_custom_icons().len() == 1);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_different_databases(_ctx: &mut MergeTestContext) {
    let (source, mut target) = create_test_dbs_5();

    println!(
        "Source db groups {:?}",
        source
            .keepass_main_content()
            .root
            .get_all_groups(false)
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<String>>()
    );

    let target_db = target.keepass_main_content.as_mut().unwrap();

    if let Some(g) = target_db.root.root_group_as_mut() {
        g.set_name("Root");
    }

    println!(
        "target_db groups {:?}",
        target_db
            .root
            .get_all_groups(false)
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<String>>()
    );

    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_mut().unwrap();

    println!(
        "target_db groups {:?}",
        target_db
            .root
            .get_all_groups(false)
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<String>>()
    );
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_moveto_recycle_bin(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    util::test_clock::advance_by(1);

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let g2 = source_db.root.group_by_name("group2").unwrap().clone();
    let group = create_group(source_db, "group22", &g2.get_uuid());
    let _ = create_entry(source_db, "entry22", &group.get_uuid());

    util::test_clock::advance_by(1);

    source_db
        .root
        .move_group_to_recycle_bin(group.get_uuid())
        .unwrap();

    let ids = source_db
        .root
        .recycle_bin_group()
        .unwrap()
        .sub_group_uuids()
        .clone();
    println!("Source Recycled groups {:?}", ids);

    for id in ids {
        let g = source_db.root.group_by_id(&id).unwrap();
        let cid = g.entry_uuids();
        println!("Source recycled entry id {:?} in group {}", cid, g.name());
    }

    let _merge_result = Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_mut().unwrap();
    let ids = target_db
        .root
        .recycle_bin_group()
        .unwrap()
        .sub_group_uuids()
        .clone();

    println!("Target Recycled groups {:?}", ids);

    for id in ids {
        let g = target_db.root.group_by_id(&id).unwrap();
        let cid = g.entry_uuids();
        println!("Target recycled entry id {:?} in group {}", cid, g.name());
    }
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_deletions(_ctx: &mut MergeTestContext) {
    let (mut source, mut target) = create_test_dbs_4();

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let target_db = target.keepass_main_content.as_ref().unwrap();

    // Adbvance time to simulate detetion in different time
    util::test_clock::advance_by(1);

    let g2 = source_db.root.group_by_name("group2").unwrap().clone();
    let e2 = source_db
        .root
        .entry_by_matching_kv(TITLE, "entry2")
        .unwrap()
        .clone();

    delete_group_permanently(source_db, &g2.get_uuid());

    // Before merge target should not have any deleted objtect
    let target_db_deleted_objects = target_db.root.deleted_objects();
    assert!(target_db_deleted_objects.is_empty());

    // Merge source to the target
    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    let target_db = target.keepass_main_content.as_ref().unwrap();
    let target_db_deleted_objects = target_db.root.deleted_objects().clone();

    assert!(target_db_deleted_objects.len() == 2);

    // Both group and its entry should be in the deleted objects of the target
    let r = target_db_deleted_objects
        .iter()
        .filter(|d| [g2.get_uuid(), e2.get_uuid()].contains(&d.uuid))
        .count();

    assert!(r == 2);
}

#[test_context(MergeTestContext)]
#[test]
fn verify_merge_deletions_2(_ctx: &mut MergeTestContext) {
    let (mut source, _) = create_test_dbs_4();

    // Adbvance time to simulate creation of data in different time
    util::test_clock::advance_by(1);

    let source_db = source.keepass_main_content.as_mut().unwrap();
    let g2 = source_db.root.group_by_name("group2").unwrap().clone();
    let group = create_group(source_db, "group22", &g2.get_uuid());
    let _ = create_entry(source_db, "entry22", &group.get_uuid());

    // Now create target from this source
    let mut target = source.clone();

    // Adbvance time to simulate detetion in different time
    util::test_clock::advance_by(1);

    // Delete "group22" in source
    // This deletes group22 and its child "entry22"
    let source_db = source.keepass_main_content.as_mut().unwrap();
    delete_group_permanently(source_db, &group.get_uuid());

    // source db has some deleted objects
    let source_db_deleted_objects = source_db.root.deleted_objects();
    //println!("Source Dos before {:?}", source_db_deleted_objects);
    assert!(source_db_deleted_objects.len() == 2);

    // Adbvance time to simulate modification in different time
    util::test_clock::advance_by(1);

    // Modify entry entry22 in target
    let target_db = target.keepass_main_content.as_mut().unwrap();
    let _ = find_update_entry(target_db, "entry22", TITLE, "entry22 changed");

    // Now merge the source to the target
    Merger::from_kdbx_file(&source, &mut target)
        .merge()
        .unwrap();

    // As entry22 is modified in target after the deletion time of group22 and entry22 in source
    // The whole group is retained
    let target_db = target.keepass_main_content.as_ref().unwrap();
    let target_db_deleted_objects = target_db.root.deleted_objects().clone();

    // println!(" Dos after {:?}", target_db_deleted_objects);

    assert!(target_db_deleted_objects.is_empty());
}
