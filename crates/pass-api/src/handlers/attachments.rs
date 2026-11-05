//! The attachments of entries across the boundary (pass-docs, Step 102): bytes only - the app picks the file and
//! writes the one downloaded, the core never sees a path.
//!
//! New attachments come with the form of their entry (`insert_entry_from_form_data`,
//! `update_entry_from_form_data`): `new_attachments` in the arguments lists their names and sizes, the bytes slot
//! of the call carries their bytes one after another in that order. A bridge call has one slot, hence the list.
//! The rest of the attachments of an entry travel in its form (`binary_key_values`): an attachment is removed by
//! leaving it out. "Download" is `entry_attachment_bytes`: the bytes of one attachment in the slot of the answer.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kdbx_rust_core::db_content::AttachmentHashValue;
use kdbx_rust_core::db_service::{self, NewAttachment};

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::{ok_envelope, ErrorPayload};
use crate::handlers::{args, reject_bytes};

/// Arguments naming one attachment of an open database: its hash, as the form spells it (`data_hash`, a string).
#[derive(Deserialize)]
struct AttachmentArgs {
    db_key: String,
    #[serde(with = "kdbx_rust_core::service_util::from_or_to::string")]
    data_hash: AttachmentHashValue,
}

/// What comes with the bytes: their length, for the caller to check the slot by.
#[derive(Serialize)]
struct AttachmentBytes {
    size: usize,
}

/// The bytes of one attachment, in the slot of the answer - as a save hands the file back, never base64 in json.
/// No such attachment - `NotFound`. The copy of `pass-api` goes to the bridge, which wipes it after the frame.
pub(crate) fn entry_attachment_bytes(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::EntryAttachmentBytes, input)?;
    let args: AttachmentArgs = args(args_json)?;

    let mut bytes = db_service::entry_attachment_bytes(&args.db_key, &args.data_hash)
        .map_err(|e| ErrorPayload::of(&e))?;

    Ok(Answer {
        envelope: ok_envelope(&AttachmentBytes { size: bytes.len() })?,
        payload: Some(std::mem::take(&mut *bytes)),
    })
}

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
