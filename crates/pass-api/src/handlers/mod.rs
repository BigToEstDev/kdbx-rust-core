//! One module per block of commands, and the pieces every block needs.
//!
//! `dispatch` keeps the match over `Command` - that is where the compiler checks nothing was forgotten -
//! and the work itself lives here, a file per block of the api: the life cycle of a database file,
//! groups, entries, and so on. With around forty five commands in v1 a single file would be long past
//! the point where the match is readable, and a block is exactly the unit that gets added, reviewed and
//! tested together.
//!
//! What a handler is: a function taking the json of its arguments (and the bytes, when the command
//! carries a database) and returning an `Answer`. Nothing else - no locking, no state of its own. The
//! core owns the open databases.

pub(crate) mod attachments;
pub(crate) mod entries;
pub(crate) mod generator;
pub(crate) mod groups;
pub(crate) mod history;
pub(crate) mod integrity;
pub(crate) mod lifecycle;
pub(crate) mod merge;
pub(crate) mod otp;
pub(crate) mod search;
pub(crate) mod settings;
pub(crate) mod trash;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::{ok_envelope, ErrorPayload};

/// The answer of a command that changed something and has nothing to report back.
///
/// A bare `{"ok":null}` would work on the wire, but it gives the contract file no shape to pin and
/// Kotlin no type to decode; a named field does both, and reads as an answer rather than as an
/// accident.
#[derive(Serialize)]
pub(crate) struct Done {
    pub(crate) done: bool,
}

impl Done {
    /// An answer carrying nothing but the fact that the call went through.
    pub(crate) fn answer() -> Result<Answer, ErrorPayload> {
        Ok(Answer {
            envelope: ok_envelope(&Done { done: true })?,
            payload: None,
        })
    }
}

/// An answer that is json and no bytes - what all but the file commands return.
pub(crate) fn json_answer<T: Serialize>(value: &T) -> Result<Answer, ErrorPayload> {
    Ok(Answer {
        envelope: ok_envelope(value)?,
        payload: None,
    })
}

/// Arguments that are required: an empty object is not a valid substitute, because a missing db_key is a
/// bug in the caller rather than a request for a default.
pub(crate) fn args<T: DeserializeOwned>(args_json: &str) -> Result<T, ErrorPayload> {
    serde_json::from_str(args_json).map_err(|e| {
        ErrorPayload::bridge(
            "InvalidArguments",
            format!("The arguments could not be read: {}", e),
        )
    })
}

/// Arguments where absent means "the core's defaults".
pub(crate) fn args_or_default<T: DeserializeOwned + Default>(
    args_json: &str,
) -> Result<T, ErrorPayload> {
    if args_json.trim().is_empty() {
        return Ok(T::default());
    }

    args(args_json)
}

pub(crate) fn require_bytes(
    command: Command,
    input: Option<Vec<u8>>,
) -> Result<Vec<u8>, ErrorPayload> {
    input.ok_or_else(|| {
        ErrorPayload::bridge(
            "InvalidArguments",
            format!("The command {:?} needs the bytes of a database", command),
        )
    })
}

/// Commands that take no bytes refuse them rather than ignore them - a caller that sends bytes to the
/// wrong command has a bug, and silence would hide it.
pub(crate) fn reject_bytes(command: Command, input: Option<Vec<u8>>) -> Result<(), ErrorPayload> {
    match input {
        None => Ok(()),
        Some(bytes) => Err(ErrorPayload::bridge(
            "InvalidArguments",
            format!(
                "The command {:?} takes no bytes, but {} were sent",
                command,
                bytes.len()
            ),
        )),
    }
}
