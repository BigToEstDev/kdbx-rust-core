//! The history of an entry: what it looked like before each save.
//!
//! kdbx keeps old versions inside the entry itself, so there is no separate object here - only an index
//! into the list the entry carries. The index is the position in that list, not an identity: deleting
//! one renumbers the rest, which is why the ui reloads the summary after every delete.

use serde::Deserialize;

use kdbx_rust_core::db_service;
use uuid::Uuid;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::{args, json_answer, reject_bytes, Done};

/// Arguments naming the entry whose history is meant.
#[derive(Deserialize)]
struct EntryIdArgs {
    db_key: String,
    entry_uuid: Uuid,
}

/// Arguments naming one version in that history.
#[derive(Deserialize)]
struct HistoryIndexArgs {
    db_key: String,
    entry_uuid: Uuid,
    /// Position in the history of the entry, as `history_entries_summary` answered it
    index: i32,
}

/// The versions of an entry, oldest first - as kdbx keeps them - with enough of each to draw a row.
pub(crate) fn history_entries_summary(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::HistoryEntriesSummary, input)?;
    let args: EntryIdArgs = args(args_json)?;

    let entries = db_service::history_entries_summary(&args.db_key, &args.entry_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&entries)
}

/// One old version as a form, so the ui can show it the way it shows the entry itself.
pub(crate) fn history_entry_by_index(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::HistoryEntryByIndex, input)?;
    let args: HistoryIndexArgs = args(args_json)?;

    let form = db_service::history_entry_by_index(&args.db_key, &args.entry_uuid, args.index)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&form)
}

/// Drops one old version. An index with no version there, or an entry that is not there, is refused with
/// `NotFound` and nothing is deleted; the ui reloads the summary afterwards, as the indexes move.
pub(crate) fn delete_history_entry_by_index(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DeleteHistoryEntryByIndex, input)?;
    let args: HistoryIndexArgs = args(args_json)?;

    db_service::delete_history_entry_by_index(&args.db_key, &args.entry_uuid, args.index)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Drops the whole history of an entry, which is the only way to shrink a database that grew on saves.
pub(crate) fn delete_history_entries(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DeleteHistoryEntries, input)?;
    let args: EntryIdArgs = args(args_json)?;

    db_service::delete_history_entries(&args.db_key, &args.entry_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}
