//! The attachments of entries across the boundary (pass-docs, Step 102): bytes only - the app picks the file and
//! writes the one downloaded, the core never sees a path.
//!
//! New attachments come with the form of their entry (`insert_entry_from_form_data`,
//! `update_entry_from_form_data`): `new_attachments` in the arguments lists their names and sizes, the bytes slot
//! of the call carries their bytes one after another in that order. A bridge call has one slot, hence the list.
//! The rest of the attachments of an entry travel in its form (`binary_key_values`): an attachment is removed by
//! leaving it out.

use zeroize::Zeroizing;

use kdbx_rust_core::db_service::NewAttachment;

use crate::commands::Command;
use crate::errors::ErrorPayload;

/// The bytes of the new attachments of a form, out of the slot of the call - wrapped by the caller as soon as it gets
/// them, so they are wiped on any refusal (pass-docs, Step 102). No new attachments - no bytes, as before
/// attachments; a list with no bytes or bytes with no list is a bug of the caller and refused. Whether the sizes
/// cover the bytes is the core's to check, with the rest of the form; the core wipes the buffer handed to it.
pub(crate) fn new_attachment_bytes(
    command: Command,
    new_attachments: &[NewAttachment],
    input: Option<Zeroizing<Vec<u8>>>,
) -> Result<Vec<u8>, ErrorPayload> {
    match (new_attachments.is_empty(), input) {
        (true, None) => Ok(Vec::new()),
        (false, Some(mut bytes)) => Ok(std::mem::take(&mut *bytes)),
        (true, Some(bytes)) => Err(ErrorPayload::bridge(
            "InvalidArguments",
            format!(
                "The command {:?} got {} bytes but no new attachments",
                command,
                bytes.len()
            ),
        )),
        (false, None) => Err(ErrorPayload::bridge(
            "InvalidArguments",
            format!(
                "The command {:?} got {} new attachments but no bytes",
                command,
                new_attachments.len()
            ),
        )),
    }
}
