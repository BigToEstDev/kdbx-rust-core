//! The attachments of the entries, as bytes: the core neither reads nor writes any file of its own for them
//! (pass-docs, Step 102). The app picks the file and writes the one downloaded - SAF on android, the dialog of the
//! desktop - and hands the bytes over the bridge: no decrypted copy lands in a temp dir.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::{db_content::AttachmentHashValue, db_service::call_kdbx_context_action, util};

use super::{call_kdbx_context_mut_action, KdbxContext};

pub use crate::error::{Error, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct AttachmentUploadInfo {
    pub name: String,
    #[serde(with = "util::from_or_to::string")]
    pub data_hash: AttachmentHashValue,
    pub data_size: usize,
}

/// Keeps `data` - the content of a file named `file_name` - among the attachments of the database `db_key`. Only the
/// bytes are kept: the caller links the returned info with an entry, in its form, the way every attachment of an
/// entry is linked; bytes linked with no entry are not written to the file.
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

/// Writes the bytes of the attachment `data_hash` of the database `db_key` to `writer`.
pub fn save_attachment_to_writer<W: Write>(
    db_key: &str,
    data_hash: &AttachmentHashValue,
    writer: &mut W,
) -> Result<()> {
    let data = call_kdbx_context_action(db_key, |ctx: &KdbxContext| {
        Ok(ctx.kdbx_file.get_bytes_content(data_hash))
    })?;

    if let Some(v) = data {
        writer.write_all(&v)?;
        Ok(())
    } else {
        Err(Error::UnexpectedError("No valid data found".into()))
    }
}
