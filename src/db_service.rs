// These are sub modules from dir db_service
// db_service.rs is used instead of mod.rs in dir db_service

mod attachment;
mod custom_icon;
mod io;

// Note: Moved module storage to db_service_ffi crate as it is used only in mobile apps for now

// Modules storage and callback_service are used for now only in mobile apps
//#[cfg(any( target_os = "ios",target_os = "android"))]
//pub mod callback_service;
// #[cfg(any( target_os = "ios",target_os = "android"))]
// pub mod storage;

use crate::db::{self, KdbxFile};
use crate::db_content::{Entry, KeepassFile, OtpData};
use crate::db_merge;
use crate::searcher;
use crate::util;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use chrono::NaiveDateTime;
use log::debug;
use uuid::Uuid;

//    ========  Re-exports to use in all api users ============

pub use attachment::{
    read_entry_attachment, remove_app_temp_dir_content, save_attachment_as,
    save_attachment_as_temp_file, save_attachment_to_writter, upload_entry_attachment,
    AttachmentUploadInfo,
};

// For now, as some fns are used only in desktop, need to include
// all fns from this module so that desktop and mobile compilation
// works
pub use io::*;

// pub use io::{
//     create_and_write_to_writer, create_kdbx, generate_key_file, load_kdbx,
//     read_and_verify_db_file, read_kdbx,
//     reload_kdbx, save_all_modified_dbs_with_backups, save_as_kdbx,
//     save_kdbx_to_writer, save_kdbx_with_backup, save_to_db_file,
// };

pub use crate::error::{self, Error, Result};

pub use crate::password_generator::{AnalyzedPassword, PasswordGenerationOptions, PasswordScore};

// See lib.rs where util module is reexported as service_util
// TDOO: Rename 'util' module as 'service_util' to avoid confilts with other crates 'util' module
pub use crate::service_util;

pub use crate::db::{
    calculate_db_file_checksum, Compression, FileKey, KdbxVersion, KeyStoreOperation,
    KeyStoreService, KeyStoreServiceType, NewDatabase, SecureKeyInfo, KEY_FILE_MAX_SIZE,
    PASSWORD_MAX_CHARS,
};

pub use crate::db_content::{
    AllTags, EntryCloneOption, FieldDataType, Group, GroupSortCriteria, OtpSettings,
};

pub use crate::form_data::{
    CredentialsUsed, CurrentOtpTokenData, DbSettings, EntryCategory, EntryFormData,
    EntryListOtpToken, EntrySummary, GroupSummary, GroupTree, KdbxLoaded, KdbxSaved, TrashEntry,
};

pub use crate::constants::entry_keyvalue_key;

pub use crate::db_merge::MergeResult;

pub use crate::custom_icons::{CustomIconData, CustomIconSummary};

pub use custom_icon::{
    add_custom_icon, get_custom_icon, list_custom_icons, remove_custom_icon, set_entry_custom_icon,
    set_group_custom_icon,
};

#[derive(Serialize, Deserialize, Debug)]
pub enum SaveStatus {
    Success,
    Failed(String),
    Message(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SaveAllResponse {
    pub db_key: String,
    pub save_status: SaveStatus,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdbxContextStatus {
    pub last_read_time: NaiveDateTime,
    pub last_write_time: NaiveDateTime,
    pub save_pending: bool,
}

pub fn kdbx_context_statuses(db_key: &str) -> Result<KdbxContextStatus> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(KdbxContextStatus {
            last_read_time: ctx.last_read_time,
            last_write_time: ctx.last_write_time,
            save_pending: ctx.save_pending,
        })
    })
}
pub(crate) struct KdbxContext {
    pub(crate) kdbx_file: KdbxFile,
    // The time of the most recent reading of the database
    pub(crate) last_read_time: NaiveDateTime, // Need to use NaiveDateTime::signed_duration_since to get duration from this
    //  The time of the most recent writing to the database
    pub(crate) last_write_time: NaiveDateTime,
    pub(crate) save_pending: bool,
    // Whether the database is currently locked (UI-authorization state). A fresh
    // open/create starts unlocked.
    pub(crate) locked: bool,
    // Memory-security lock: while `locked`, the decrypted content is removed
    // from `kdbx_file.keepass_main_content` and held here as ciphertext (encrypted
    // with the session enc key). Restored on unlock. `None` when unlocked or when the
    // caller only toggled the `locked` flag without encrypting content.
    pub(crate) locked_content_blob: Option<Vec<u8>>,
}

// Need to implement Default explicitly as there is no default support in NaiveDateTime
impl Default for KdbxContext {
    fn default() -> Self {
        Self {
            kdbx_file: KdbxFile::default(),
            last_read_time: util::now_utc(),
            last_write_time: util::now_utc(),
            save_pending: false,
            locked: false,
            locked_content_blob: None,
        }
    }
}

// Both callers are desktop only - create_kdbx and write_new_db_kdbx_file, which persist a new
// database by path. On mobile a new database is created through create_and_write_to_writer and
// reaches the cache from there, so without this cfg the Android build warns about dead code.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl KdbxContext {
    // Add the newly created KdbxFile to cache for UI use
    fn insert(kdbx_file: KdbxFile) {
        let db_key = kdbx_file.get_database_file_name().to_string();
        let kdbx_context = KdbxContext {
            kdbx_file,
            ..Default::default()
        };
        let mut store = main_store().lock().unwrap();
        store.insert(db_key, kdbx_context);
    }
}

// Here we're using an Arc to share memory among threads, and the data - HashMap<String, KdbxContext> - inside
// the Arc is protected with a mutex.
// The keys of inner HashMap are from 'db_key' of each opened database
type MainStore = Arc<Mutex<HashMap<String, KdbxContext>>>;

fn main_store() -> &'static MainStore {
    static MAIN_STORE: Lazy<MainStore> = Lazy::new(Default::default);
    &MAIN_STORE
}

// Gets a ref to the main keepass content
#[macro_export]
macro_rules! to_keepassfile {
    ($kdbx_file:expr) => {
        // Need to get Option<&KeepassFile> from Option<KeepassFile> using as_ref
        $kdbx_file
            .keepass_main_content
            .as_ref()
            .ok_or("No main content")?
    };
}

#[macro_export]
macro_rules! to_keepassfile_mut {
    ($kdbx_file:expr) => {
        // Need to get Option<&KeepassFile> from Option<KeepassFile> using as_ref
        $kdbx_file
            .keepass_main_content
            .as_mut()
            .ok_or("No main content")?
    };
}

// A macro to do a db query and then update the last read time for tracking
#[macro_export]
macro_rules! main_content_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_main_content_action($db_key, $closure_fn);
        // Update the read time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_read_time = util::now_utc();
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_main_content_action($db_key, $closure_fn)
    };
}

// A macro to call a db modification and then update the last write time for tracking
#[macro_export]
macro_rules! main_content_mut_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_main_content_mut_action($db_key, $closure_fn);
        // Update the write time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_write_time = $crate::util::now_utc();
            ctx.save_pending = true;
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr, no_times) => {
        // No write time update is done when the caller passes 'no_times' at the end
        call_main_content_mut_action($db_key, $closure_fn)
    };
}

// A macro to call a db reading and then update the last read time for tracking
#[macro_export]
macro_rules! kdbx_context_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_kdbx_context_action($db_key, $closure_fn);
        // Update the read time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_read_time = util::now_utc();
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_kdbx_context_action($db_key, $closure_fn)
    };
}

#[macro_export]
macro_rules! kdbx_context_mut_action {
    ($db_key:expr,$closure_fn:expr) => {{
        let r = call_kdbx_context_mut_action($db_key, $closure_fn);
        // Update the write time
        call_kdbx_context_mut_action($db_key, |ctx: &mut KdbxContext| {
            ctx.last_write_time = util::now_utc();
            ctx.save_pending = true;
            Ok(())
        })?;
        r
    }};
    ($db_key:expr,$closure_fn:expr ,no_times) => {
        // No read time update is done when the caller passes 'no_times' at the end
        call_kdbx_context_action($db_key, $closure_fn)
    };
}

// Calls the action closure with the complete context for a specific db
pub(crate) fn call_kdbx_context_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&KdbxContext) -> Result<T>,
{
    let store = main_store().lock().unwrap();
    // Gets the stored KdbxContext for the key "db_key"
    match store.get(db_key) {
        Some(kdbx_context) => action(kdbx_context),
        None => Err(Error::DbKeyNotFound),
    }
}

// Calls the mut action closure with the complete context for a specific db
pub(crate) fn call_kdbx_context_mut_action<T, F>(db_key: &str, mut action: F) -> Result<T>
where
    F: FnMut(&mut KdbxContext) -> Result<T>,
{
    let mut store = main_store().lock().unwrap();
    //Gets the stored KdbxContext for the key "db_key"
    match store.get_mut(db_key) {
        Some(kdbx_context) => action(kdbx_context),
        None => Err(Error::DbKeyNotFound),
    }
}

// Calls the action closure with the db content for a specific db
pub(crate) fn call_main_content_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&KeepassFile) -> Result<T>,
{
    let store = main_store().lock().unwrap();
    // First we need to get the context and then get the stored KdbxFile for the key "db_key"
    match store.get(db_key) {
        Some(kdbx_context) => match &kdbx_context.kdbx_file.keepass_main_content {
            // Call the closure with the keepassFile content.
            // We cannot return ref to Entry or Group or Meta from the action.
            // This is because the return ref cannot outlive the borrowed ref (store -> kbdx_file -> k)
            // The borrowed ref 'store' will be dropped at the end of this
            // So we need to clone if we want to return the content to the caller
            Some(k) => action(k),
            None => Err(error::Error::NotFound(
                "Keepass main content in not found".into(),
            )),
        },
        None => Err(error::Error::DbKeyNotFound),
    }
}

// Calls the mut action closure with the db content for a specific db
pub(crate) fn call_main_content_mut_action<T, F>(db_key: &str, action: F) -> Result<T>
where
    F: Fn(&mut KeepassFile) -> Result<T>,
{
    let mut store = main_store().lock().unwrap();
    // First we need to get the mut context and then get the stored mut KdbxFile for the key "db_key"
    match store.get_mut(db_key) {
        Some(kdbx_context) => match &mut kdbx_context.kdbx_file.keepass_main_content {
            // Call the closure with the keepassFile content.
            // We cannot return ref to Entry or Group or Meta from the action.
            // This is because the return ref cannot outlive the borrowed ref (store -> kbdx_file -> k)
            // The borrowed ref 'store' will be dropped at the end of this
            // So we need to clone if we want to return the content to the caller
            Some(k) => action(k),
            None => Err(Error::NotFound("Keepass main content in not found".into())),
        },
        None => Err(Error::DbKeyNotFound),
    }
}

pub fn all_kdbx_cache_keys() -> Result<Vec<String>> {
    let store = main_store().lock().unwrap();
    let mut vec = vec![];
    for k in store.keys() {
        vec.push(k.clone());
    }
    Ok(vec)
}

// Sets/clears the locked flag for an open database. Locking is a UI-authorization
// state; toggling it does NOT mark the database dirty (so we use the direct mut
// action rather than the `kdbx_context_mut_action!` macro, which bumps
// save_pending/last_write_time).
pub fn set_db_locked(db_key: &str, locked: bool) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        ctx.locked = locked;
        Ok(())
    })
}

pub fn is_db_locked(db_key: &str) -> Result<bool> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| Ok(ctx.locked))
}

// Memory-security lock. Encrypts the decrypted content in place (only
// ciphertext remains in RAM while locked) and marks the db locked. Idempotent: a
// second call while already locked is a no-op. Unsaved edits are preserved (we
// encrypt the live content, not discard it), so no save is forced here.
//
// Reuses the existing per-session enc key (already in the OS key store from the
// open/create) - no new secret. The enc key is intentionally NOT removed on lock
// since it is needed to decrypt on unlock.
pub fn lock_kdbx(db_key: &str) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        if !ctx.locked {
            ctx.locked_content_blob = ctx.kdbx_file.lock_content(db_key)?;
            ctx.locked = true;
        }
        Ok(())
    })
}

// Decrypts the held content blob back into `keepass_main_content` and clears the
// locked flag. Safe to call when there is no blob (e.g. the flag was toggled
// without content encryption, or on mobile which does not encrypt content yet) -
// it just clears the flag. Callers should invoke this BEFORE reading any content
// (e.g. building KdbxLoaded metadata).
fn restore_locked_content(db_key: &str) -> Result<()> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        if let Some(blob) = ctx.locked_content_blob.take() {
            ctx.kdbx_file.unlock_content(db_key, &blob)?;
        }
        ctx.locked = false;
        Ok(())
    })
}

pub fn is_db_opened(db_key: &str) -> bool {
    let store = main_store().lock().unwrap();
    store.contains_key(db_key)
}

// Gets the previously calculated checksum for a db found under the db_key
pub fn db_checksum_hash(db_key: &str) -> Result<Vec<u8>> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.checksum_hash().clone())
    })
}

pub fn close_all_databases() -> Result<()> {
    if let Ok(keys) = all_kdbx_cache_keys() {
        for k in keys {
            let _r = close_kdbx(&k);
        }
    }
    Ok(())
}

// Removes the previously opened KDBX file from cache
pub fn close_kdbx(db_key: &str) -> Result<()> {
    let mut store = main_store().lock().unwrap();
    // UI side save is handled for any changes.
    // As an additional check, on the backendside, we may need to verify that all changes are persisted and
    // ask the user to save or not if there are any unsaved changes
    store.remove(db_key);
    KeyStoreOperation::delete_key(db_key)?;
    Ok(())
}

// Mobile (iOS and Android)
// Called to rename the db key used and the database_file_name as we know
// the full db file name and db_key are used interchangeably
// Used mainly in 'complete_save_as_on_error' call

// See db_service::ios::save_as_kdbx for desktop version where db_key is the
// actual file to which content is written. Here we are changing map key

// TODO: Combine these two

pub fn rename_db_key(old_db_key: &str, new_db_key: &str) -> Result<KdbxLoaded> {
    // Need to copy the encrytion key for the new name from the existing one
    KeyStoreOperation::copy_key(old_db_key, new_db_key)?;

    let kdbx_loaded = call_kdbx_context_mut_action(old_db_key, |ctx: &mut KdbxContext| {
        ctx.kdbx_file.set_database_file_name(new_db_key);

        Ok(KdbxLoaded {
            db_key: new_db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            // TODO: Check the use of 'None' values below fields in iOS and Android after this Save as call
            //       We may need to update in db-service_ffi crate before sending back to UI
            file_name: None,
            key_file_name: None,
        })
    })?;

    // As the db_file_name is changed, we need to reset the db key to this new name
    let mut store = main_store().lock().unwrap();
    if let Some(v) = store.remove(old_db_key) {
        store.insert(new_db_key.into(), v);
    }

    // Remove the old encryption key for the old db_key
    KeyStoreOperation::delete_key(old_db_key)?;

    Ok(kdbx_loaded)
}

// Called after user has successfully completed the biometeric based authentication
pub fn unlock_kdbx_on_biometric_authentication(db_key: &str) -> Result<KdbxLoaded> {
    // Restore the decrypted content and clear the locked flag FIRST, so the
    // metadata below is read from restored content. When there is no locked
    // content blob (a db opened but never locked, or the autofill path which
    // does not encrypt), this only clears the flag.
    restore_locked_content(db_key)?;

    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        Ok(KdbxLoaded {
            db_key: db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            file_name: util::file_name(db_key),
            key_file_name: ctx.kdbx_file.get_key_file_name(),
        })
    })
}

// Compares the entered credentials with the stored one for a quick unlock of the db.
// The key file is built by the caller - from a path or from bytes, see FileKey
pub fn unlock_kdbx(
    db_key: &str,
    password: Option<&str>,
    file_key: Option<FileKey>,
) -> Result<KdbxLoaded> {
    // Verify credentials against the stored composite key. This works while the
    // content is encrypted: compare_key uses the composite key, not the
    // decrypted content.
    let matched = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        ctx.kdbx_file.compare_key(password, &file_key)
    })?;
    if !matched {
        // Same error as if db file verification failure happening in load_kdbx.
        // On mismatch we return early, leaving the locked state untouched.
        return Err(Error::InvalidCredentials);
    }

    // Credentials matched — restore the decrypted content and clear the locked flag,
    // then read the metadata from the restored content.
    restore_locked_content(db_key)?;

    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        Ok(KdbxLoaded {
            db_key: db_key.into(),
            database_name: ctx.kdbx_file.get_database_name().into(),
            file_name: util::file_name(db_key),
            key_file_name: ctx.kdbx_file.get_key_file_name(),
        })
    })
}

// Whether `password` is the password of the open database - checked alone, the key file of the database
// not asked for: what the app asks before it keeps the password for biometrics (Step 60). A database
// without a password matches none. Locked or not, nothing changes: neither the content nor the lock.
pub fn verify_password(db_key: &str, password: &str) -> Result<bool> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        ctx.kdbx_file.matches_password(password)
    })
}

// Whether the key of the open database has a password, a key file or both (Step 60)
pub fn credentials_used(db_key: &str) -> Result<CredentialsUsed> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        let (password, key_file) = ctx.kdbx_file.credentials_used_state();
        Ok(CredentialsUsed { password, key_file })
    })
}

// How long one KDF pass of the open database takes on this device (Step 68): the open time is one pass
// times the iterations. Only the parameters are copied under the store lock - the pass itself runs
// outside, other calls do not wait for it. Locked or not, the database is not changed
pub fn measure_kdf_pass(db_key: &str) -> Result<Duration> {
    let kdf = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_kdf_algorithm())
    })?;
    kdf.measure_pass()
}

// Returns the human-readable name of the database identified by `db_key`.
pub fn get_db_name(db_key: &str) -> Result<String> {
    let action = |k: &KeepassFile| Ok(k.meta.database_name().clone());
    main_content_action!(db_key, action, no_times)
}

// Gather all unique tags that are used in all groups and entries
pub fn collect_entry_group_tags(db_key: &str) -> Result<AllTags> {
    main_content_action!(db_key, move |k: &KeepassFile| Ok(k.root.collect_tags()))
}

pub fn get_db_settings(db_key: &str) -> Result<DbSettings> {
    kdbx_context_action!(db_key, |ctx: &KdbxContext| {
        let kp = to_keepassfile!(ctx.kdbx_file);

        let key_file_name = ctx.kdbx_file.get_key_file_name();
        //Used only in Mobile apps
        let key_file_name_part = key_file_name.as_ref().and_then(|s| util::file_name(s));

        let (password_used, key_file_used) = ctx.kdbx_file.credentials_used_state();

        let db_settings = DbSettings {
            kdf: ctx.kdbx_file.get_kdf_algorithm(),
            cipher_id: ctx.kdbx_file.get_content_cipher_id(),
            password: None,
            key_file_name,
            password_used,
            key_file_used,
            password_changed: false,
            key_file_changed: false,
            key_file_name_part,
            database_file_name: ctx.kdbx_file.get_database_file_name().to_string(),
            kdbx_version: ctx.kdbx_file.get_version(),
            compression: ctx.kdbx_file.get_compression(),
            meta: (&kp.meta).into(),
        };
        Ok(db_settings)
    })
}

// The settings come back as get_db_settings gave them, edited. The key file, when it changes, comes
// beside them as content (file_key), built by the caller - from bytes on mobile, from a path on desktop,
// see FileKey. `key_file_name` inside the settings is never read: it is what get_db_settings shows, and
// a name to show cannot be told from a path, so taking it as input would mean opening whatever it says.
//
// Everything is checked before anything changes: a refusal leaves the database as it was, name and all.
pub fn set_db_settings(
    db_key: &str,
    db_settings: DbSettings,
    file_key: Option<FileKey>,
) -> Result<()> {
    if db_settings.password_changed {
        db::check_new_password(db_settings.password.as_deref())?;
    }

    kdbx_context_mut_action!(db_key, |ctx: &mut KdbxContext| {
        let db_settings = db_settings.clone();
        let file_key = file_key.clone();

        // IMPORTANT
        // password_used, key_file_used, password_changed and key_file_changed are set from client side
        // in a consistent way satisfying the following combinations
        // If a password is changed, then password_used = true, password_changed = true and password = Some value
        // If the password use is removed,
        //     then password_used = false, password_changed = true, password = None;
        //          and a key file has to stay - the current one or a new one
        // If a key file is changed,
        //      then key_file_used = true, key_file_changed = true, file_key = Some
        // If the key file use is removed,
        //      then key_file_used = false, key_file_changed = true, file_key = None; and a password has to stay

        debug!(
            "password_used: {}, password_changed: {}, password is nil?: {}, key_file_used: {}, key_file_changed: {}, key file: {:?}",
            db_settings.password_used,
            db_settings.password_changed,
            db_settings.password.is_none(),
            db_settings.key_file_used,
            db_settings.key_file_changed,
            file_key.as_ref().map(|f| f.file_name())
        );

        // A key file is content only when it changes to a new one; anywhere else it would mean the
        // caller expects a key file the settings will not apply
        match (
            db_settings.key_file_used,
            db_settings.key_file_changed,
            &file_key,
        ) {
            (true, true, None) => {
                return Err(Error::DataError(
                    "The new key file is required when the key file is changed",
                ));
            }
            (true, true, Some(_)) => {}
            (_, _, Some(_)) => {
                return Err(Error::DataError(
                    "A key file is passed, but the settings do not change it to a new one",
                ));
            }
            (_, _, None) => {}
        }

        // Without a change the key file stays what the database has now; the flag has to agree with that
        let (_, key_file_in_use) = ctx.kdbx_file.credentials_used_state();
        if !db_settings.key_file_changed && db_settings.key_file_used != key_file_in_use {
            return Err(Error::DataError(
                "The key file is said to be unchanged, but its use differs from the database",
            ));
        }

        // Both password and key file can not be none at the same time
        if !db_settings.password_used && !db_settings.key_file_used {
            return Err(error::Error::InSufficientCredentials);
        }

        // Password is used and expected some value when it is changed or added
        if db_settings.password_used
            && db_settings.password_changed
            && db_settings.password.is_none()
        {
            return Err(Error::DataError("Password can not be empty"));
        }

        if !db_settings.password_used && db_settings.password.is_some() {
            return Err(Error::DataError(
                "Password is not used, but found some value",
            ));
        }

        // password is considered only when it is changed
        let password = if db_settings.password_used && db_settings.password_changed {
            db_settings.password.as_deref()
        } else {
            None
        };

        // Every check has passed - only now anything changes
        let kp = ctx
            .kdbx_file
            .keepass_main_content
            .as_mut()
            .ok_or("No main content")?;
        kp.meta.update((&db_settings.meta).into())?;

        if db_settings.password_changed && db_settings.key_file_changed {
            // Both password and key file use changed
            ctx.kdbx_file.set_credentials(db_key, password, file_key)?;
        } else if db_settings.password_changed {
            // Only password changed
            ctx.kdbx_file.set_password(password)?;
        } else if db_settings.key_file_changed {
            // Only the key file changed: a new one, or none
            ctx.kdbx_file.set_file_key(file_key)?;
        }

        ctx.kdbx_file.set_kdf_algorithm(db_settings.kdf)?;
        ctx.kdbx_file.set_content_cipher_id(db_settings.cipher_id)?;
        // kdbx_version is not read: the file is written as 4.1 whatever it says
        ctx.kdbx_file.set_compression(db_settings.compression);

        // Like KeePass after its settings dialog: new history limits apply to all entries now, not
        // only to entries edited later. Done last, after every validation above has passed - as the
        // recycle bin switched off, which removes the bin with all it holds
        if let Some(kp) = ctx.kdbx_file.keepass_main_content.as_mut() {
            kp.maintain_all_histories();
            kp.set_recycle_bin_enabled(db_settings.meta.recycle_bin_enabled)?;
        }
        Ok(())
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntrySearchResult {
    pub term: String,
    pub entry_items: Vec<EntrySummary>,
}

/// The entries found by a term, with the term itself beside them.
///
/// An entry is found by its title or its user name - the values its card shows, place holders resolved -
/// holding the term as plain text, case aside; a protected field is never looked into. Entries in the
/// recycle bin, in the groups inside it too, are not looked at. A blank term finds nothing. The entries
/// come in no particular order: the caller sorts them.
pub fn search_term(db_key: &str, term: &str) -> Result<EntrySearchResult> {
    main_content_action!(db_key, |k: &KeepassFile| {
        let entry_items = match searcher::normalized_term(term) {
            None => vec![],
            Some(needle) => k
                .collect_all_active_entries()
                .into_iter()
                .filter_map(|e| {
                    let summary = EntrySummary::of(k, e);
                    searcher::matches(&needle, e, &summary).then_some(summary)
                })
                .collect(),
        };
        Ok(EntrySearchResult {
            term: term.into(),
            entry_items,
        })
    })
}

/// The entries of the recycle bin, from any depth of it: groups get there only from other apps (KeePass,
/// KeePassXC) and are not shown (Step 69). The entries come in no particular order: the caller sorts them.
pub fn trash_entries(db_key: &str) -> Result<Vec<TrashEntry>> {
    main_content_action!(db_key, |k: &KeepassFile| {
        Ok(k.root
            .deleted_entries()
            .into_iter()
            .map(|e| TrashEntry::of(k, e))
            .collect())
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TrashSearchResult {
    pub term: String,
    pub entry_items: Vec<TrashEntry>,
}

/// The entries of the recycle bin found by a term - the same match as `search_term`, over `trash_entries`.
pub fn search_trash(db_key: &str, term: &str) -> Result<TrashSearchResult> {
    main_content_action!(db_key, |k: &KeepassFile| {
        let entry_items = match searcher::normalized_term(term) {
            None => vec![],
            Some(needle) => k
                .root
                .deleted_entries()
                .into_iter()
                .map(|e| (e, TrashEntry::of(k, e)))
                .filter(|(e, item)| searcher::matches(&needle, e, &item.entry))
                .map(|(_, item)| item)
                .collect(),
        };
        Ok(TrashSearchResult {
            term: term.into(),
            entry_items,
        })
    })
}

// Adjusts the special groups are such as recycle bin group listed
// in the end of the child group ids in case of root group
fn adjust_special_groups_order(k: &KeepassFile, group: &Group) -> Vec<String> {
    if k.root.root_uuid() == group.uuid {
        let v: Vec<String> = group
            .group_uuids
            .iter()
            .filter(|x| !k.root.special_group_uuids().contains(x))
            .map(|x| x.to_string())
            .collect();

        [
            v,
            k.root
                .special_group_uuids()
                .iter()
                .map(|x| x.to_string())
                .collect(),
        ]
        .concat()
    } else {
        group.group_uuids.iter().map(|x| x.to_string()).collect()
    }
}

// Create as group summary data for all groups
// Returns the group tree data
fn create_groups_summary_data(k: &KeepassFile) -> Result<GroupTree> {
    let mut grps: HashMap<String, GroupSummary> = HashMap::new();
    // All groups including special groups (e.g Recycle Bin Group) are collected
    // to form summary. Need to pass 'false' to include all groups
    for group in &k.root.get_all_groups(false) {
        grps.insert(
            group.get_uuid().to_string(),
            GroupSummary {
                uuid: group.get_uuid(),
                parent_group_uuid: group.parent_group_uuid(),
                name: group.name.clone(),
                icon_id: group.icon_id,
                custom_icon_uuid: group.custom_icon_uuid.map(|u| u.to_string()),
                group_uuids: adjust_special_groups_order(k, group),
                entry_uuids: group.entry_uuids.iter().map(|x| x.to_string()).collect(),
            },
        );
    }
    Ok(GroupTree {
        root_uuid: k.root.root_uuid(),
        recycle_bin_uuid: k.root.recycle_bin_uuid(),
        deleted_group_uuids: k.deleted_group_uuids(),
        groups: grps,
    })
}

pub fn groups_summary_data(db_key: &str) -> Result<GroupTree> {
    main_content_action!(db_key, create_groups_summary_data)
}

pub fn mark_group_as_category(db_key: &str, group_id: &str) -> Result<()> {
    let gid = Uuid::parse_str(group_id)?;
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        k.root.mark_group_as_category(&gid);
        Ok(())
    })
}

pub fn entry_summary_data(
    db_key: &str,
    entry_category: EntryCategory,
) -> Result<Vec<EntrySummary>> {
    let action = |k: &KeepassFile| {
        // let mut entries = EntrySummary::entry_summary_data(form_data::entry_by_category(&k, &entry_category));
        let mut entries = EntrySummary::entry_summary_data(k, &entry_category);
        // for now sort just by the title
        entries.sort_unstable_by(|a, b| a.title.cmp(&b.title));
        Ok(entries)
    };
    main_content_action!(db_key, action)
}
pub fn get_group_by_id(db_key: &str, group_uuid: &Uuid) -> Result<Group> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.group_by_id(group_uuid) {
            Some(g) => Ok(g.clone()),
            None => Err(Error::NotFound("No group Entry found for the id".into())),
        }
    })
}

pub fn get_entry_form_data_by_id(db_key: &str, entry_uuid: &Uuid) -> Result<EntryFormData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            // Need to parse and resolve place holders found in some entry fields
            Some(e) => Ok(EntryFormData::place_holder_resolved_form_data(&k.root, e)),
            None => Err(Error::NotFound(format!(
                "No entry is found for the id {}",
                entry_uuid
            ))),
        }
    })
}

// Gets the current TOTP token for one otp field of an entry.
// Crate-internal: the only caller is async_service (form_first_reply / form_reply), the UI drives
// otp polling through async_service. entry_list_current_otps is the list-side counterpart.
pub(crate) fn entry_form_current_otp(
    db_key: &str,
    entry_uuid: &Uuid,
    otp_field_name: &str,
) -> Result<CurrentOtpTokenData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => match e.current_otp_token_data(otp_field_name) {
                Some(pd) => Ok(pd),
                None => Err(Error::UnexpectedError(format!(
                    "Current TOPT token data is not available for the field: {}",
                    otp_field_name
                ))),
            },
            None => Err(Error::NotFound(format!(
                "No entry is found for the id {}",
                entry_uuid
            ))),
        }
    })
}

// Gets the current token of every entry in 'entry_uuids' that has one
//
// Entries with no otp field, with an unparseable otp url, or with several otp fields and
// no standard one are simply absent from the result - see Entry::list_otp_token_data. So a
// caller showing codes on a list needs no separate 'does this entry have 2FA' query, and
// one call serves a whole page of rows
pub fn entry_list_current_otps(
    db_key: &str,
    entry_uuids: &[Uuid],
) -> Result<Vec<EntryListOtpToken>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        let tokens = entry_uuids
            .iter()
            .filter_map(|entry_uuid| {
                let entry = k.root.entry_by_id(entry_uuid)?;
                let (otp_field_name, data) = entry.list_otp_token_data()?;
                Some(EntryListOtpToken {
                    entry_uuid: entry_uuid.to_string(),
                    otp_field_name,
                    token: data.token,
                    ttl: data.ttl,
                    period: data.period,
                })
            })
            .collect();
        Ok(tokens)
    })
}

#[inline]
pub fn form_otp_url(otp_settings: &OtpSettings) -> Result<String> {
    otp_settings.otp_url()
}

#[inline]
pub fn is_valid_otp_url(otp_url_str: &str) -> bool {
    OtpData::from_url(otp_url_str).is_ok()
}

// Sets or replaces the 2fa of an entry, in whichever format that entry already uses: the
// TimeOtp-* fields of the original KeePass 2.47+ (keeping the encoding its secret was in) or an
// `otpauth://` url in the `otp` field, which is also what an entry with no 2fa yet gets. The
// format is decided here rather than by the caller so that a database written by KeePass keeps
// working in KeePass, and so the rule is covered by the core's own tests - see Entry::set_otp.
//
// The settings are validated first: a secret that cannot be decoded, or a period or length the core
// does not support, leaves the entry untouched. A version is added to the entry's history as with
// any other edit.
pub fn set_entry_otp(db_key: &str, entry_uuid: &Uuid, otp_settings: &OtpSettings) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        let mut updated_entry = match k.root.entry_by_id(entry_uuid) {
            Some(e) => e.clone(),
            None => return Err(Error::NotFound("No entry found for the id".into())),
        };
        updated_entry.set_otp(otp_settings)?;
        k.root.update_entry(updated_entry)
    })
}

// Removes the 2fa of an entry without leaving a tail: every TimeOtp field and the `otp` field go
pub fn delete_entry_otp(db_key: &str, entry_uuid: &Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        let mut updated_entry = match k.root.entry_by_id(entry_uuid) {
            Some(e) => e.clone(),
            None => return Err(Error::NotFound("No entry found for the id".into())),
        };
        updated_entry.remove_otp();
        k.root.update_entry(updated_entry)
    })
}

// Collects all entry field names and its values (not in any particular order)
pub fn entry_key_value_fields(db_key: &str, entry_uuid: &Uuid) -> Result<HashMap<String, String>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        EntryFormData::entry_key_value_fields(k, entry_uuid)
    })
}

pub fn history_entry_by_index(
    db_key: &str,
    entry_uuid: &Uuid,
    index: i32,
) -> Result<EntryFormData> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.history_entry_by_index(entry_uuid, index) {
            Some(ref e) => Ok(e.into()),
            None => Err(Error::NotFound("No entry Entry found for the id".into())),
        }
    })
}

pub fn delete_history_entry_by_index(db_key: &str, entry_uuid: &Uuid, index: i32) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.delete_history_entry_by_index(entry_uuid, index)
    })
}

pub fn delete_history_entries(db_key: &str, entry_uuid: &Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.delete_history_entries(entry_uuid)
    })
}

pub fn history_entries_summary(db_key: &str, entry_uuid: &Uuid) -> Result<Vec<EntrySummary>> {
    main_content_action!(db_key, move |k: &KeepassFile| {
        match k.root.entry_by_id(entry_uuid) {
            Some(e) => Ok(EntrySummary::history_entries_summary(e)),
            None => Err(Error::NotFound("No entry Entry found for the id".into())),
        }
    })
}

pub fn update_entry_from_form_data(db_key: &str, form_data: EntryFormData) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.update_entry(Entry::try_from(&form_data)?)
    })
}

pub fn insert_entry_from_form_data(db_key: &str, form_data: EntryFormData) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // entry.meta_share is not yet set when EntryFormData is converted to
        // an Entry. It is set in Keepass's insert_entry which in turn
        // calls k.root.insert_entry
        k.insert_entry(Entry::try_from(&form_data)?)
    })
}

pub fn clone_entry(
    db_key: &str,
    entry_uuid: &Uuid,
    entry_clone_option: &EntryCloneOption,
) -> Result<Uuid> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.clone_entry(entry_uuid, entry_clone_option)
    })
}

pub fn clone_group(db_key: &str, group_uuid: &Uuid, new_name: Option<String>) -> Result<Uuid> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.clone_group(group_uuid, new_name.clone())
    })
}

pub fn update_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, |k: &mut KeepassFile| {
        k.root.update_group(group.clone(), false);
        Ok(())
    })
}

// Called from UI layer to insert a newly added group
pub fn insert_group(db_key: &str, group: Group) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // Delegate to the fn in root
        k.root.insert_group(group.clone())
    })
}

pub fn sort_sub_groups(
    db_key: &str,
    group_uuid: &Uuid,
    criteria: &GroupSortCriteria,
) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        // Delegate to the fn in root
        k.root.sort_sub_groups(group_uuid, criteria)
    })
}

/// Deletes a group with its subtree: the entries go to the recycle bin flat, the groups are removed for good.
/// With the bin off (`RecycleBinEnabled`) everything is removed for good. Groups never go to the bin (Step 69)
pub fn delete_group(db_key: &str, group_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.delete_group(group_uuid)
    })
}

pub fn move_group(db_key: &str, group_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_group(group_uuid, new_parent_id)
    })
}

/// Deletes an entry: into the recycle bin, or for good with the bin off (`RecycleBinEnabled`)
pub fn delete_entry(db_key: &str, entry_uuid: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.delete_entry(entry_uuid)
    })
}

pub fn move_entry(db_key: &str, entry_uuid: Uuid, new_parent_id: Uuid) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| {
        k.root.move_entry(entry_uuid, new_parent_id)
    })
}

pub fn empty_trash(db_key: &str) -> Result<()> {
    main_content_mut_action!(db_key, move |k: &mut KeepassFile| { k.empty_trash() })
}

// The form of a new entry, with the kdbx standard fields - nothing of the database is needed for it
pub fn new_entry_form_data(parent_group_uuid: Option<&Uuid>) -> EntryFormData {
    EntryFormData::new_form_entry(parent_group_uuid)
}

pub fn new_blank_group(mark_as_category: bool) -> Group {
    let mut group = Group::new_with_id();
    // group.uuid = uuid::Uuid::new_v4();
    if mark_as_category {
        group.mark_as_category();
        //group.custom_data.mark_as_category();
    }
    group
}

pub fn new_blank_group_with_parent(
    parent_group_uuid: Uuid,
    mark_as_category: bool,
) -> Result<Group> {
    if parent_group_uuid == Uuid::default() {
        return Err(Error::UnexpectedError(
            "Valid parent group is not provided".into(),
        ));
    }
    let mut group = new_blank_group(mark_as_category);
    group.parent_group_uuid = parent_group_uuid;
    Ok(group)
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn merge_databases(
    target_db_key: &str,
    source_db_key: &str,
    password: Option<&str>,
    key_file_name: Option<&str>,
) -> Result<MergeResult> {
    if target_db_key == source_db_key {
        return Err(error::Error::UnexpectedError("Both source and target are the same databases. Please select a different database to merge".to_string()));
    }

    // IMPORTANT:
    // We need to call all the calls 'main_store().lock()' to access the shared cache in a {} block
    // so that the Mutex guard is unlocked while leaving the block and can then called again in another block or fn
    // If not done this way, the deadlock will happen when we make calls to 'main_store().lock()' before unlocking the previous call

    let source_already_opened = {
        let store = main_store().lock().unwrap();
        store.contains_key(source_db_key)
    };

    log::debug!("source_already_openned is {}", source_already_opened);

    let source_loaded = if !source_already_opened {
        load_kdbx(source_db_key, password, key_file_name)?;
        log::debug!("source is opened");
        true
    } else {
        false
    };

    let merge_result = {
        let mut store = main_store().lock().unwrap();
        let [target, source] = store.get_disjoint_mut([target_db_key, source_db_key]);
        log::debug!("Got refs for source and target");

        let target_kdbx = &mut target.ok_or("Target database key is not found")?.kdbx_file;
        let source_kdbx = &source
            .as_ref()
            .ok_or("Source database key is not found")?
            .kdbx_file;
        let merge_result = db_merge::Merger::from_kdbx_file(source_kdbx, target_kdbx).merge()?;
        log::debug!("Dbs are merged");

        merge_result
    };

    if source_loaded {
        close_kdbx(source_db_key)?;
        log::debug!("source_db_key closed as it was opened only for merging");
    }

    Ok(merge_result)
}

// Merges a kdbx loaded from an arbitrary reader into the in-memory version.
// Same shape as merge_kdbx_with_disk_version but reads bytes from the
// caller-supplied reader (used by the remote-storage path on both desktop and
// mobile, where the "other side" lives on SFTP/WebDAV rather than disk).
pub fn merge_kdbx_with_reader<R: std::io::Read + std::io::Seek>(
    db_key: &str,
    reader: &mut R,
) -> Result<MergeResult> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        let other_kdbx = db::reload(reader, &ctx.kdbx_file).map_err(|e| match e {
            Error::InvalidCredentials => Error::MergeFailedCredentialsChanged,
            other => other,
        })?;

        let merge_result =
            db_merge::Merger::from_kdbx_file(&other_kdbx, &mut ctx.kdbx_file).merge()?;

        ctx.kdbx_file.checksum_hash = db::calculate_db_file_checksum(reader)?;
        ctx.save_pending = true;

        Ok(merge_result)
    })
}

// Desktop-only: merges the on-disk version of the DB into the in-memory version.
// Uses the stored composite key — no credential re-entry needed.
// Sets save_pending = true on success so the UI knows unsaved changes exist.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub fn merge_kdbx_with_disk_version(db_key: &str) -> Result<MergeResult> {
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        // Load the on-disk version which will decrypted using the stored composite key.
        let mut reader = db::open_db_file(db_key)?;

        debug!("The db file {} is loaded to merge", db_key);

        // if let Some(kc) = ctx.kdbx_file.keepass_main_content.as_ref() {
        //     debug!("before merging Ctx all entries count{} ", kc.root.all_entries().len());
        // }

        // debug!(ctx.kdbx_file.all_entries);
        // db::reload() clones ctx.kdbx_file (including encrypted composite key) and decrypts.
        // If the on-disk file was re-encrypted with different credentials, reload returns
        // InvalidCredentials — remap it to a specific error so the frontend can
        // show a targeted message instead of a generic "invalid credentials" prompt.
        let disk_kdbx = db::reload(&mut reader, &ctx.kdbx_file).map_err(|e| match e {
            Error::InvalidCredentials => Error::MergeFailedCredentialsChanged,
            other => other,
        })?;

        debug!("Db is reloaded from file system");

        // if let Some(kc) = disk_kdbx.keepass_main_content.as_ref() {
        //     debug!("Disk all entries count {} ", kc.root.all_entries().len());
        // }

        // Merge: disk version = source, in-memory version = target
        let merge_result =
            db_merge::Merger::from_kdbx_file(&disk_kdbx, &mut ctx.kdbx_file).merge()?;

        // Update checksum to the on-disk state so the watcher won't re-fire for this change.
        // calculate_db_file_checksum rewinds reader internally before reading.
        ctx.kdbx_file.checksum_hash = db::calculate_db_file_checksum(&mut reader)?;
        ctx.save_pending = true;

        // if let Some(kc) = ctx.kdbx_file.keepass_main_content.as_ref() {
        //     debug!("After merging Ctx all entries count{} ", kc.root.all_entries().len());
        // }

        Ok(merge_result)
    })
}

#[cfg(any(target_os = "ios", target_os = "android"))]
pub fn merge_databases(target_db_key: &str, source_db_key: &str) -> Result<MergeResult> {
    if target_db_key == source_db_key {
        return Err(error::Error::UnexpectedError(format!("Both source and target are the same databases. Please select a different database to merge")));
    }

    let merge_result = {
        let mut store = main_store().lock().unwrap();
        let [target, source] = store.get_disjoint_mut([target_db_key, source_db_key]);
        log::debug!("Got refs for source and target");

        let target_kdbx = &mut target
            .ok_or_else(|| "Target database key is not found")?
            .kdbx_file;
        let source_kdbx = &source
            .as_ref()
            .ok_or_else(|| "Source database key is not found")?
            .kdbx_file;
        let merge_result = db_merge::Merger::from_kdbx_file(source_kdbx, target_kdbx).merge()?;
        log::debug!("Dbs are merged");

        merge_result
    };

    Ok(merge_result)
}
