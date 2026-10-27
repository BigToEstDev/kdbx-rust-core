//! Search across the whole database, and the tags it holds.
//!
//! Searching is not a filter over a list the ui already has: the core looks at every entry of the
//! database, matches the title and the user name as a card shows them - place holders resolved - and
//! leaves out a field marked protected, which only it knows of. So the term goes to it rather than the
//! entries coming here. The answer carries the term back, which is what lets a screen drop the result
//! of a search the user has already typed past.

use serde::Deserialize;

use kdbx_rust_core::db_service;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::lifecycle::DbKeyArgs;
use crate::handlers::{args, json_answer, reject_bytes};

#[derive(Deserialize)]
struct SearchArgs {
    db_key: String,
    /// What to look for, as plain text: the title and the user name of an entry, case aside, never a
    /// protected field
    term: String,
}

/// The entries matching a term, with the term itself beside them.
pub(crate) fn search_term(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::SearchTerm, input)?;
    let args: SearchArgs = args(args_json)?;

    let found =
        db_service::search_term(&args.db_key, &args.term).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&found)
}

/// Every tag in the database, of entries and of groups separately - what a tag picker offers.
pub(crate) fn collect_entry_group_tags(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CollectEntryGroupTags, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let tags =
        db_service::collect_entry_group_tags(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&tags)
}
