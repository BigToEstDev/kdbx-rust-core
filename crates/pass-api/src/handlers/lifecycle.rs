//! Creating, reading, saving and closing the database file.
//!
//! The file itself belongs to Android: the app picks it through SAF and this library never sees a path.
//! So a database travels as bytes beside the arguments - in for reading, out for creating and saving -
//! and the core reads and writes a `Cursor` over them. Both of its functions are generic over
//! `Read + Seek` / `Read + Write + Seek`, so nothing in the core had to change for this.
//!
//! Why bytes rather than the file descriptor SAF could hand over: `File::from_raw_fd` is unsafe by
//! contract and would put the one unsafe block of the project in the middle of the data path, together
//! with the ownership rule that comes with `detachFd`. The price is the database in memory twice for the
//! length of a call - it is a few megabytes, and they are the *encrypted* bytes of the file.
//!
//! A key file is behind SAF just the same, so it travels as content too - inside the json arguments,
//! see `key_file`.

use std::io::Cursor;

use serde::{Deserialize, Serialize};

use kdbx_rust_core::db_service::{self, NewDatabase};

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::{ok_envelope, ErrorPayload};
use crate::handlers::{args, json_answer, reject_bytes, require_bytes, Done};
use crate::key_file::{file_key_of, KeyFileArg};

/// Arguments of every command that works on an open database.
#[derive(Deserialize)]
pub(crate) struct DbKeyArgs {
    /// The uri of the database file, which is also its identity in the core's store
    pub(crate) db_key: String,
}

/// Arguments of `read_kdbx`. The bytes of the file arrive beside them, not inside.
#[derive(Deserialize)]
struct ReadKdbxArgs {
    db_key: String,
    password: Option<String>,
    #[serde(default)]
    key_file: Option<KeyFileArg>,
    /// The name to show. Passed in because the core would otherwise derive it from `db_key`, and a SAF
    /// uri has no readable file name in it
    file_name: Option<String>,
}

/// Arguments of `create_and_write_to_writer`: the fields of `NewDatabase` itself, and the key file next
/// to them.
///
/// `NewDatabase` is the one place where a core type is the argument type: its fields are private and it
/// can only be built through serde, so its own shape is the shape of the arguments. Flattened rather than
/// nested, so the arguments stay what they were plus one field. Its own `key_file_name` is a desktop
/// path and is refused by the core here - the key file is `key_file`.
#[derive(Deserialize)]
struct CreateArgs {
    #[serde(flatten)]
    new_db: NewDatabase,
    #[serde(default)]
    key_file: Option<KeyFileArg>,
}

/// Creates a database and hands its bytes back for Kotlin to write through SAF.
pub(crate) fn create(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CreateAndWriteToWriter, input)?;
    let args: CreateArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let mut buffer = Cursor::new(Vec::<u8>::new());
    let loaded = db_service::create_and_write_to_writer(&mut buffer, args.new_db, file_key)
        .map_err(|e| ErrorPayload::of(&e))?;

    Ok(Answer {
        envelope: ok_envelope(&loaded)?,
        payload: Some(buffer.into_inner()),
    })
}

/// Opens the database whose bytes were sent along, and leaves it open in the core's store.
pub(crate) fn read(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    let bytes = require_bytes(Command::ReadKdbx, input)?;
    let args: ReadKdbxArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let mut reader = Cursor::new(bytes);
    let loaded = db_service::read_kdbx(
        &mut reader,
        &args.db_key,
        args.password.as_deref(),
        file_key,
        args.file_name.as_deref(),
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&loaded)
}

/// Writes the open database into a buffer and hands the bytes back.
pub(crate) fn save(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::SaveKdbxToWriter, input)?;
    let args: DbKeyArgs = args(args_json)?;

    // A fresh buffer, never the previous contents of the file: `save_kdbx_to_writer` does not truncate
    // its writer, and a shorter database would otherwise keep the tail of the older one
    let mut buffer = Cursor::new(Vec::<u8>::new());
    let saved = db_service::save_kdbx_to_writer(&mut buffer, &args.db_key)
        .map_err(|e| ErrorPayload::of(&e))?;

    Ok(Answer {
        envelope: ok_envelope(&saved)?,
        payload: Some(buffer.into_inner()),
    })
}

/// Drops the database from the core's store, keys and all.
pub(crate) fn close(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CloseKdbx, input)?;
    let args: DbKeyArgs = args(args_json)?;

    db_service::close_kdbx(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Arguments of `unlock_kdbx`: the same credentials as opening, checked against the stored key.
#[derive(Deserialize)]
struct UnlockArgs {
    db_key: String,
    password: Option<String>,
    #[serde(default)]
    key_file: Option<KeyFileArg>,
}

/// Arguments of `rename_db_key`: the file moved, or "save as" wrote it somewhere else.
#[derive(Deserialize)]
struct RenameArgs {
    /// The uri the database is known by now
    old_db_key: String,
    /// The uri it should be known by from here on
    new_db_key: String,
}

/// Arguments of `verify_password`: the password alone - the key file, when the database has one, is the
/// core's to know.
#[derive(Deserialize)]
struct VerifyPasswordArgs {
    db_key: String,
    password: String,
}

#[derive(Serialize)]
struct Locked {
    locked: bool,
}

#[derive(Serialize)]
struct Matches {
    matches: bool,
}

#[derive(Serialize)]
struct Opened {
    opened: bool,
}

/// Locks the database in memory: the decrypted content is encrypted in place, so only ciphertext is
/// left in RAM. Unsaved edits survive - the live content is encrypted, not dropped - so this is not a
/// save and does not need one.
pub(crate) fn lock(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::LockKdbx, input)?;
    let args: DbKeyArgs = args(args_json)?;

    db_service::lock_kdbx(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Unlocks it again with the credentials. They are checked against the stored composite key, which
/// works while the content is still encrypted - a wrong password never touches the content.
pub(crate) fn unlock(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::UnlockKdbx, input)?;
    let args: UnlockArgs = args(args_json)?;
    let file_key = file_key_of(args.key_file)?;

    let loaded = db_service::unlock_kdbx(&args.db_key, args.password.as_deref(), file_key)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&loaded)
}

/// Whether the database is locked - what the app asks when it comes back to the foreground.
pub(crate) fn is_locked(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::IsDbLocked, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let locked = db_service::is_db_locked(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&Locked { locked })
}

/// Whether the core still holds this database at all.
///
/// Unlike the rest, this one cannot fail: a database that is not open is the answer `false`, not a
/// `DbKeyNotFound` - the question exists precisely to be asked about a database that may be gone,
/// after the process was killed and restarted.
pub(crate) fn is_opened(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::IsDbOpened, input)?;
    let args: DbKeyArgs = args(args_json)?;

    json_answer(&Opened {
        opened: db_service::is_db_opened(&args.db_key),
    })
}

/// Whether the password is the one of the open database - checked alone against the hash the core kept,
/// without the key file and without the KDF, so it answers at once. What the app asks before it keeps the
/// password for biometrics (Step 60). A wrong one is the answer `false`, not a failure.
pub(crate) fn verify_password(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::VerifyPassword, input)?;
    let args: VerifyPasswordArgs = args(args_json)?;

    let matches = db_service::verify_password(&args.db_key, &args.password)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&Matches { matches })
}

/// What the key of the open database is made of: a password, a key file or both. A database without a
/// password is not offered biometrics - there is nothing to keep (Step 60).
pub(crate) fn credentials_used(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CredentialsUsed, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let used = db_service::credentials_used(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&used)
}

/// Tells the core that the file now lives under another uri - after "save as", or after the user moved
/// or renamed it. The stored encryption key is copied over to the new name by the core.
pub(crate) fn rename_db_key(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::RenameDbKey, input)?;
    let args: RenameArgs = args(args_json)?;

    let loaded = db_service::rename_db_key(&args.old_db_key, &args.new_db_key)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&loaded)
}

/// Unlocks the database without asking for the password, on the strength of an authentication that
/// already happened on the Android side.
///
/// The check is not here and cannot be: the biometric prompt is Android's, and what it guards is the
/// key in the Android Keystore. This command is what follows a prompt that has already succeeded -
/// it restores the decrypted content, nothing more. So it is only ever as safe as the Keystore work
/// in front of it, which is why the two belong together (decision 5 of Step 23) and why the in
/// memory key store of today is not the end of it.
pub(crate) fn unlock_on_biometric(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::UnlockKdbxOnBiometricAuthentication, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let loaded = db_service::unlock_kdbx_on_biometric_authentication(&args.db_key)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&loaded)
}

/// When the database was last read and written, and whether it has edits that are not in the file.
///
/// `save_pending` is the only way to know there is something to save, so it is what an "unsaved
/// changes" prompt and the automatic save on going to the background are built on.
pub(crate) fn context_statuses(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::KdbxContextStatuses, input)?;
    let args: DbKeyArgs = args(args_json)?;

    let statuses =
        db_service::kdbx_context_statuses(&args.db_key).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&statuses)
}
