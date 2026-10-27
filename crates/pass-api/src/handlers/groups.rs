//! Groups: the tree, one group, and the operations that change it.
//!
//! A group is the core's own `Group` in both directions here, and that is on purpose. Everywhere else
//! the arguments are our own structs, because the core's names carry the history of the format; a group
//! is the exception, because `insert_group` and `update_group` take a whole `Group` and there is no
//! smaller honest way to pass one - a hand written subset would quietly drop the fields the core reads
//! and writes back (`custom_data`, the unknown elements of another program's database), and saving
//! would lose them. The round trip is: the ui asks for a blank group or an existing one, edits the
//! fields it shows, and sends the same object back.
//!
//! Uuids arrive as strings and are parsed by serde, so a malformed one is `InvalidArguments` before any
//! database is touched.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use kdbx_rust_core::db_service::{self, Group, GroupSortCriteria};

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::lifecycle::DbKeyArgs;
use crate::handlers::{args, json_answer, reject_bytes, Done};

/// Arguments naming one group of an open database.
#[derive(Deserialize)]
struct GroupIdArgs {
    db_key: String,
    group_uuid: Uuid,
}

/// Arguments carrying a whole group - inserting a new one, or updating an existing one.
#[derive(Deserialize)]
struct GroupArgs {
    db_key: String,
    group: Group,
}

/// A blank group needs no database: the core builds it from nothing, and the ui fills it in.
#[derive(Deserialize)]
struct NewBlankGroupArgs {
    /// Mark the group as a category, which is how the ui groups tiles on the home screen
    mark_as_category: bool,
}

#[derive(Deserialize)]
struct NewBlankGroupWithParentArgs {
    parent_group_uuid: Uuid,
    mark_as_category: bool,
}

#[derive(Deserialize)]
struct MoveGroupArgs {
    db_key: String,
    group_uuid: Uuid,
    /// The group it moves into
    new_parent_uuid: Uuid,
}

#[derive(Deserialize)]
struct SortSubGroupsArgs {
    db_key: String,
    group_uuid: Uuid,
    criteria: SortCriteria,
}

#[derive(Deserialize)]
struct CloneGroupArgs {
    db_key: String,
    group_uuid: Uuid,
    /// The name of the copy; absent means the core keeps the name of the original
    new_name: Option<String>,
}

/// How to sort the groups inside a group.
///
/// The core spells the same two choices `AtoZ` / `ZtoA`. Arguments are ours and snake_case throughout,
/// so the wire keeps `a_to_z` / `z_to_a` and the mapping stays in this one place rather than in the
/// Kotlin models.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SortCriteria {
    AToZ,
    ZToA,
}

impl From<SortCriteria> for GroupSortCriteria {
    fn from(criteria: SortCriteria) -> Self {
        match criteria {
            SortCriteria::AToZ => GroupSortCriteria::AtoZ,
            SortCriteria::ZToA => GroupSortCriteria::ZtoA,
        }
    }
}

/// The uuid of a freshly cloned group. The core answers with a bare uuid; a named field gives the
/// contract file a shape and Kotlin a type.
#[derive(Serialize)]
struct ClonedGroup {
    group_uuid: Uuid,
}

/// The whole tree in one answer: every group by uuid, plus the root and the recycle bin.
///
/// One call rather than a walk from the root, because the ui draws the tree at once and the core has it
/// in memory anyway - a call per level would be dozens of crossings of the boundary for one screen.
pub(crate) fn groups_summary_data(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::GroupsSummaryData, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let tree = db_service::groups_summary_data(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&tree)
}

/// One group with all of its fields - what the edit screen needs, and what goes back on update.
pub(crate) fn get_group_by_id(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::GetGroupById, input)?;
    let args: GroupIdArgs = args(args_json)?;

    let group = db_service::get_group_by_id(&args.db_key, &args.group_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&group)
}

/// A group that exists nowhere yet: it has a uuid but no parent, so the ui fills the parent in.
pub(crate) fn new_blank_group(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::NewBlankGroup, input)?;
    let args: NewBlankGroupArgs = args(args_json)?;

    json_answer(&db_service::new_blank_group(args.mark_as_category))
}

/// The same, with the parent already set - the usual case, "add a group inside this one".
pub(crate) fn new_blank_group_with_parent(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::NewBlankGroupWithParent, input)?;
    let args: NewBlankGroupWithParentArgs = args(args_json)?;

    let group =
        db_service::new_blank_group_with_parent(args.parent_group_uuid, args.mark_as_category)
            .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&group)
}

/// Puts a new group into the tree. The group carries its own parent.
pub(crate) fn insert_group(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::InsertGroup, input)?;
    let args: GroupArgs = args(args_json)?;

    db_service::insert_group(&args.db_key, args.group).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Writes an edited group back. Moving it is `move_group`, not a changed parent here.
pub(crate) fn update_group(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::UpdateGroup, input)?;
    let args: GroupArgs = args(args_json)?;

    db_service::update_group(&args.db_key, args.group).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Moves a group into another group, with everything inside it.
pub(crate) fn move_group(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::MoveGroup, input)?;
    let args: MoveGroupArgs = args(args_json)?;

    db_service::move_group(&args.db_key, args.group_uuid, args.new_parent_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Sorts the child groups of a group by name. It is stored order, not a view option: the order is
/// written into the file.
pub(crate) fn sort_sub_groups(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::SortSubGroups, input)?;
    let args: SortSubGroupsArgs = args(args_json)?;

    db_service::sort_sub_groups(&args.db_key, &args.group_uuid, &args.criteria.into())
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Copies a group with its subtree, and answers with the uuid of the copy.
pub(crate) fn clone_group(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CloneGroup, input)?;
    let args: CloneGroupArgs = args(args_json)?;

    let group_uuid = db_service::clone_group(&args.db_key, &args.group_uuid, args.new_name)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&ClonedGroup { group_uuid })
}

/// The "delete" of the ui for a group with its subtree: its entries go to the recycle bin, flat, and the
/// groups go for good - only entries are kept in the bin. Without a bin everything goes for good.
pub(crate) fn delete_group(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DeleteGroup, input)?;
    let args: GroupIdArgs = args(args_json)?;

    db_service::delete_group(&args.db_key, args.group_uuid).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}
