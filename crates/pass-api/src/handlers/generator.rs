//! The password generator.
//!
//! It needs no open database: the options come in, a password goes out. That is also why it is the
//! command the bridge's own tests use - it exercises the envelope without a kdbx file in sight.

use serde::Serialize;

use kdbx_rust_core::db_service::PasswordGenerationOptions;

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::{args_or_default, json_answer, reject_bytes};

#[derive(Serialize)]
struct GeneratedPassword {
    password: String,
}

pub(crate) fn generate_password(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::GeneratePassword, input)?;
    // Absent or empty arguments mean the core's defaults
    let options: PasswordGenerationOptions = args_or_default(args_json)?;
    let password = options.generate().map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&GeneratedPassword { password })
}

/// Generates a password and rates it in the same call.
///
/// One command rather than "generate, then score it": the score belongs to that password, and two
/// calls would let the ui show a rating of a password the user is no longer looking at.
pub(crate) fn analyzed_password(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::AnalyzedPassword, input)?;
    let options: PasswordGenerationOptions = args_or_default(args_json)?;
    let analyzed = options
        .analyzed_password()
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&analyzed)
}
