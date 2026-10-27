//! Has the file changed under us, and what to do when it has.
//!
//! Three of these four commands carry the bytes of the file on disk, so they go through the binary
//! boundary - the same road the database itself travels. The checksum is over the *file*, not over
//! what the core holds, which is why the bytes have to come: the core cannot read the file, SAF owns
//! it.
//!
//! The order a save follows (decision 6 of Step 23): read the current bytes, `verify_db_file_checksum`,
//! and on `DbFileContentChangeDetected` offer the dialog; otherwise save and then
//! `calculate_and_set_db_file_checksum` over the bytes just written - not over the file read back,
//! which would be one more pass through SAF for nothing.

use std::io::Cursor;

use kdbx_rust_core::db_service;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::lifecycle::DbKeyArgs;
use crate::handlers::{args, json_answer, reject_bytes, require_bytes, Done};

/// The checksum the core remembers for this database, as raw bytes.
///
/// It is answered as the numbers it is, not as hex: the app only ever hands it back or compares it,
/// and inventing an encoding here would be one more thing for both sides to agree on.
#[derive(serde::Serialize)]
struct Checksum {
    checksum: Vec<u8>,
}

/// Compares the bytes of the file with the checksum taken when it was last read or written.
///
/// A mismatch is `DbFileContentChangeDetected` - someone else wrote the file - and that is an
/// ordinary outcome the ui answers with the merge dialog, not a breakage.
pub(crate) fn verify_db_file_checksum(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::VerifyDbFileChecksum, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let mut reader = Cursor::new(bytes);
    db_service::verify_db_file_checksum(&args.db_key, &mut reader)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Takes the checksum of these bytes and keeps it as the state of the file.
///
/// Called with the bytes just written, so the next save compares against what this app wrote rather
/// than against what it last read.
pub(crate) fn calculate_and_set_db_file_checksum(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::CalculateAndSetDbFileChecksum, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let mut reader = Cursor::new(bytes);
    db_service::calculate_and_set_db_file_checksum(&args.db_key, &mut reader)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// The checksum the core is holding, without touching the file.
pub(crate) fn db_checksum_hash(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DbChecksumHash, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let checksum = db_service::db_checksum_hash(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&Checksum { checksum })
}

/// Merges the file on disk into the database in memory.
///
/// It works on the stored composite key, so no password is asked for - and that is also why a file
/// re-encrypted elsewhere comes back as `MergeFailedCredentialsChanged` rather than as a wrong
/// password.
///
/// There is no undo: the merge changes the content in memory at once, and `different_databases` in
/// the answer is only known *after* it happened. So the warning about merging two unrelated databases
/// is shown as a fact, and "cancel" there means closing without saving - the file itself is untouched,
/// because Kotlin is what writes it.
pub(crate) fn merge_kdbx_with_reader(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::MergeKdbxWithReader, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let mut reader = Cursor::new(bytes);
    let result = db_service::merge_kdbx_with_reader(&args.db_key, &mut reader)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&result)
}
