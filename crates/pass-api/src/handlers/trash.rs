//! The recycle bin.
//!
//! Only entries go there (pass-docs, Step 69): deleting a group sends the entries of its subtree to the bin
//! and removes the groups for good. So the bin is a flat list of entries - with the group each was deleted
//! from while that group lives, which a restore offers first - its search, restoring to a group and
//! removing for good. Groups in the bin come only from other apps and are never shown; emptying takes
//! them too.
//!
//! Moving things *into* the bin is `delete_entry` / `delete_group`, which also know whether the database
//! uses a bin at all.

use serde::Deserialize;
use uuid::Uuid;

use kdbx_rust_core::db_service;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::lifecycle::DbKeyArgs;
use crate::handlers::{args, json_answer, reject_bytes, Done};

#[derive(Deserialize)]
struct SearchTrashArgs {
    db_key: String,
    /// The same as `search_term`: the title and the user name of an entry, as plain text, case aside
    term: String,
}

/// Arguments of a restore: the entries picked on the trash screen and the one group they all go to.
#[derive(Deserialize)]
struct RestoreEntriesArgs {
    db_key: String,
    entry_uuids: Vec<Uuid>,
    group_uuid: Uuid,
}

#[derive(Deserialize)]
struct EntryUuidsArgs {
    db_key: String,
    entry_uuids: Vec<Uuid>,
}

/// The entries of the bin, from any depth of it, in no particular order - the screen sorts them.
pub(crate) fn trash_entries(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::TrashEntries, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let entries = db_service::trash_entries(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&entries)
}

/// The entries of the bin matching a term, with the term itself beside them.
pub(crate) fn search_trash(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::SearchTrash, input)?;
    let args: SearchTrashArgs = args(args_json)?;

    let found =
        db_service::search_trash(&args.db_key, &args.term).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&found)
}

/// Moves entries out of the bin to a living group. All or nothing: one entry outside the bin, or a group
/// that is the bin or in it, and nothing moves.
pub(crate) fn restore_entries(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::RestoreEntries, input)?;
    let args: RestoreEntriesArgs = args(args_json)?;

    db_service::restore_entries(&args.db_key, args.entry_uuids, args.group_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Removes entries of the bin for good, all or nothing. There is no undo, so the ui asks first.
pub(crate) fn remove_entries_permanently(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::RemoveEntriesPermanently, input)?;
    let args: EntryUuidsArgs = args(args_json)?;

    db_service::remove_entries_permanently(&args.db_key, args.entry_uuids)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Empties the recycle bin: everything in it goes for good, with no undo.
pub(crate) fn empty_trash(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::EmptyTrash, input)?;
    let args: DbKeyArgs = args(args_json)?;

    db_service::empty_trash(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}
