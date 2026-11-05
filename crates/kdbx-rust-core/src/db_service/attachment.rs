//! The attachments of the entries, as bytes: the core neither reads nor writes any file of its own for them
//! (pass-docs, Step 102). The app picks the file and writes the one downloaded - SAF on android, the dialog of the
//! desktop - and hands the bytes over the bridge: no decrypted copy lands in a temp dir.
//!
//! New attachments come with the form of their entry and are linked with it in the same call: bytes uploaded on
//! their own and linked later would be gone after a write of the file in between (`AttachmentSet::drop_unlinked`).

use std::collections::HashSet;
use std::io::Write;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    db_content::{AttachmentHashValue, BinaryKeyValue, Entry},
    db_service::call_kdbx_context_action,
    form_data::EntryFormData,
    util,
};

use super::{call_kdbx_context_mut_action, KdbxContext};

pub use crate::error::{Error, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttachmentUploadInfo {
    pub name: String,
    #[serde(with = "util::from_or_to::string")]
    pub data_hash: AttachmentHashValue,
    pub data_size: usize,
}

/// A file added to an entry together with its form: the name it gets in the entry and the length of its bytes. The
/// bytes of all the new files of one form come in one buffer, one after another in the order of the list - a bridge
/// call carries one buffer only.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NewAttachment {
    pub name: String,
    pub size: usize,
}

/// Puts a filled in form into the database as a new entry, with `new_attachments` - their bytes in `data` - linked
/// with it. See `update_entry_from_form_data_with_attachments` for what is checked.
pub fn insert_entry_from_form_data_with_attachments(
    db_key: &str,
    form_data: EntryFormData,
    new_attachments: &[NewAttachment],
    data: Vec<u8>,
) -> Result<()> {
    save_form(db_key, form_data, new_attachments, data, FormSave::Insert)
}

/// Writes an edited form back, with `new_attachments` - their bytes in `data` - linked with the entry. All or nothing,
/// checked before any bytes are kept: the sizes add up to the length of `data`; the names of the attachments of the
/// entry - those of the form and the new ones - are not empty and differ; every attachment of the form is among the
/// bytes of the database. The size of an attachment of the form is taken from its bytes, not from the form. An
/// attachment is removed by leaving it out of the form.
pub fn update_entry_from_form_data_with_attachments(
    db_key: &str,
    form_data: EntryFormData,
    new_attachments: &[NewAttachment],
    data: Vec<u8>,
) -> Result<()> {
    save_form(db_key, form_data, new_attachments, data, FormSave::Update)
}

/// Keeps `data` - the content of a file named `file_name` - among the attachments of the database `db_key`. Only the
/// bytes are kept: the caller links the returned info with an entry, in its form, before the next write of the file;
/// bytes linked with no entry are gone after it. The app adds attachments with the form instead
/// (`update_entry_from_form_data_with_attachments`).
pub fn upload_entry_attachment(
    db_key: &str,
    file_name: &str,
    data: Vec<u8>,
) -> Result<AttachmentUploadInfo> {
    // The action is an FnMut: the bytes are moved in once
    let mut data = Some(data);
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        let data = data.take().unwrap_or_default();
        let size = data.len();
        let data_hash = ctx.kdbx_file.upload_entry_attachment(data)?;
        Ok(AttachmentUploadInfo {
            name: file_name.into(), // Just the file name
            data_hash,
            data_size: size,
        })
    })
}

/// The bytes of the attachment `data_hash` of the database `db_key` - a copy, the caller's to wipe once handed over
/// ("Download" of the app, pass-docs, Step 102). No such bytes - `NotFound`; a locked database has none to give.
pub fn entry_attachment_bytes(
    db_key: &str,
    data_hash: &AttachmentHashValue,
) -> Result<Zeroizing<Vec<u8>>> {
    call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        ctx.kdbx_file
            .get_bytes_content(data_hash)
            .map(Zeroizing::new)
            .ok_or_else(|| Error::NotFound("No attachment found for the hash".into()))
    })
}

/// Writes the bytes of the attachment `data_hash` of the database `db_key` to `writer`.
pub fn save_attachment_to_writer<W: Write>(
    db_key: &str,
    data_hash: &AttachmentHashValue,
    writer: &mut W,
) -> Result<()> {
    // The copy taken out of the database is wiped once handed over (pass-docs, Step 102)
    let data = entry_attachment_bytes(db_key, data_hash)?;
    writer.write_all(&data)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum FormSave {
    Insert,
    Update,
}

fn save_form(
    db_key: &str,
    form_data: EntryFormData,
    new_attachments: &[NewAttachment],
    data: Vec<u8>,
    mode: FormSave,
) -> Result<()> {
    // Wiped however the call ends: the copies kept go to the attachments of the database
    let data = Zeroizing::new(data);

    // The checks that need no database first
    let entry = Entry::try_from(&form_data)?;
    check_sizes(new_attachments, data.len())?;
    check_names(&entry, new_attachments)?;

    // The action is an FnMut: the entry is moved in once
    let mut entry = Some(entry);
    call_kdbx_context_mut_action(db_key, |ctx: &mut KdbxContext| {
        let mut entry = entry
            .take()
            .ok_or_else(|| Error::UnexpectedError("The form is saved once".into()))?;
        let kdbx = &mut ctx.kdbx_file;
        if kdbx.keepass_main_content.is_none() {
            return Err(Error::NotFound("Keepass main content in not found".into()));
        }

        // The attachments the form has: all of them among the bytes held, before any new bytes are kept
        let attachments = kdbx.attachmentset();
        for bkv in entry.binary_key_values.iter_mut() {
            bkv.data_size = attachments
                .content_size(&bkv.data_hash)
                .ok_or(Error::DataError(
                    "An attachment of the form is not among the attachments of the database",
                ))?;
        }

        let mut offset = 0;
        for new in new_attachments {
            let bytes = data[offset..offset + new.size].to_vec();
            offset += new.size;
            // A failure here leaves the bytes kept before it linked with nothing: they go with the next write
            let data_hash = kdbx.upload_entry_attachment(bytes)?;
            entry.binary_key_values.push(BinaryKeyValue {
                key: new.name.clone(),
                value: String::new(),
                // Set when the file is written, from the hash
                index_ref: 0,
                data_hash,
                data_size: new.size,
            });
        }

        let content = kdbx
            .keepass_main_content
            .as_mut()
            .ok_or_else(|| Error::NotFound("Keepass main content in not found".into()))?;
        match mode {
            FormSave::Insert => content.insert_entry(entry)?,
            FormSave::Update => content.root.update_entry(entry)?,
        }

        ctx.last_write_time = util::now_utc();
        ctx.save_pending = true;
        Ok(())
    })
}

// The new bytes are cut by the sizes, so the sizes must cover the buffer exactly
fn check_sizes(new_attachments: &[NewAttachment], data_len: usize) -> Result<()> {
    let total = new_attachments
        .iter()
        .try_fold(0usize, |total, a| total.checked_add(a.size));
    if total != Some(data_len) {
        return Err(Error::DataError(
            "The sizes of the new attachments do not add up to the bytes sent",
        ));
    }
    Ok(())
}

// The name is the key of an attachment in the entry (Binary/Key): one name, one attachment. A repeated name is the
// app's to change before the save - this is the guard behind it
fn check_names(entry: &Entry, new_attachments: &[NewAttachment]) -> Result<()> {
    let mut names = HashSet::new();
    let all = entry
        .binary_key_values
        .iter()
        .map(|b| b.key.as_str())
        .chain(new_attachments.iter().map(|a| a.name.as_str()));
    for name in all {
        if name.is_empty() {
            return Err(Error::DataError("An attachment has no name"));
        }
        if !names.insert(name) {
            return Err(Error::DataError(
                "Two attachments of the entry have the same name",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_sizes, NewAttachment};

    fn new(size: usize) -> NewAttachment {
        NewAttachment {
            name: format!("{}.bin", size),
            size,
        }
    }

    #[test]
    fn the_sizes_must_cover_the_bytes_exactly() {
        assert!(check_sizes(&[], 0).is_ok());
        assert!(check_sizes(&[new(2), new(3)], 5).is_ok());
        assert!(check_sizes(&[new(0)], 0).is_ok());

        assert!(check_sizes(&[], 1).is_err());
        assert!(check_sizes(&[new(2), new(3)], 4).is_err());
        assert!(check_sizes(&[new(2), new(3)], 6).is_err());
    }

    #[test]
    fn sizes_that_overflow_are_refused() {
        assert!(check_sizes(&[new(usize::MAX), new(1)], 0).is_err());
    }
}
