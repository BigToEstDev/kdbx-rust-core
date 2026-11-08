//! Another database file brought into the open one: a copy of it merged, or a different database imported.
//!
//! Two commands for the two buttons the user sees (pass-docs, Step 105, 106). Both carry the bytes of the
//! other file and its own credentials - a copy may have been given another password on another device, and an
//! imported database has its own anyway. The core checks the root group before anything changes: a different
//! database sent to `merge_kdbx_from_bytes` is `NotSameDatabase`, a copy sent to `import_kdbx_from_bytes` is
//! `SameDatabase`.
//!
//! Neither touches the checksum of the open file: the bytes are another file, not a newer version of this
//! one - that case is `merge_kdbx_with_reader` (`integrity`). The result is in memory only, the app saves it.
//!
//! `merge_kdbx_both_ways` (Step 109) - the merge of a copy, and the bytes of the copy's file beside its result:
//! the merged database encrypted with the copy's credentials and header, for the app to write over that file.

use std::io::Cursor;

use serde::Deserialize;

use kdbx_rust_core::db_service;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::{ok_envelope, ErrorPayload};
use crate::handlers::{args, json_answer, require_bytes};
use crate::key_file::{file_key_of, KeyFileArg};

/// Arguments of both commands: the open database, and the credentials of the other file - its bytes
/// arrive beside them.
#[derive(Deserialize)]
struct MergeArgs {
    /// The open database the other one is merged into
    db_key: String,
    password: Option<String>,
    #[serde(default)]
    key_file: Option<KeyFileArg>,
}

/// Merges another copy of the open database.
pub(crate) fn merge_kdbx_from_bytes(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::MergeKdbxFromBytes, input)?;
    let args: MergeArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let mut reader = Cursor::new(bytes);
    let result = db_service::merge_kdbx_from_bytes(
        &args.db_key,
        &mut reader,
        args.password.as_deref(),
        file_key,
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&result)
}

/// Imports a different database into the open one.
pub(crate) fn import_kdbx_from_bytes(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::ImportKdbxFromBytes, input)?;
    let args: MergeArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let mut reader = Cursor::new(bytes);
    let result = db_service::import_kdbx_from_bytes(
        &args.db_key,
        &mut reader,
        args.password.as_deref(),
        file_key,
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&result)
}

/// Merges another copy of the open database both ways: its result, and the bytes of the copy's file.
pub(crate) fn merge_kdbx_both_ways(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::MergeKdbxBothWays, input)?;
    let args: MergeArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let mut reader = Cursor::new(bytes);
    let merged = db_service::merge_kdbx_both_ways(
        &args.db_key,
        &mut reader,
        args.password.as_deref(),
        file_key,
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    Ok(Answer {
        envelope: ok_envelope(&merged.result)?,
        payload: Some(merged.copy),
    })
}
