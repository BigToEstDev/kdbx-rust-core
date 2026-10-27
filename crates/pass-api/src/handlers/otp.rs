//! Two factor codes: the tokens a list shows, and the 2fa settings of one entry.
//!
//! Tokens expire, so they are asked for rather than pushed: there are no callbacks from Rust into
//! Kotlin, and a ticking coroutine calling `entry_list_current_otps` for the visible rows is both
//! simpler and cheaper than a stream across the boundary. `ttl` in the answer is how long the token
//! the caller just got is still good for.
//!
//! Setting the 2fa of an entry does not say which format to write it in - the core decides, keeping
//! the format the entry already uses (the `TimeOtp-*` fields of KeePass 2.47+, or an `otpauth://` url),
//! so a database written by KeePass keeps working there.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use kdbx_rust_core::db_content::OtpAlgorithm;
use kdbx_rust_core::db_service::{self, OtpSettings};

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::{args, json_answer, reject_bytes, Done};

#[derive(Deserialize)]
struct CurrentOtpsArgs {
    db_key: String,
    /// The entries whose tokens are wanted - the rows on screen, not the whole database
    entry_uuids: Vec<Uuid>,
}

#[derive(Deserialize)]
struct EntryOtpArgs {
    db_key: String,
    entry_uuid: Uuid,
    #[serde(flatten)]
    settings: Settings,
}

#[derive(Deserialize)]
struct EntryIdArgs {
    db_key: String,
    entry_uuid: Uuid,
}

#[derive(Deserialize)]
struct OtpUrlArgs {
    otp_url: String,
}

/// The 2fa settings as the wire spells them.
///
/// The same four values as the core's `OtpSettings`, with the algorithm snake_case like every other
/// argument: the core names its variants `SHA1` / `SHA256` / `SHA512`, and that spelling stays on this
/// side of the boundary.
#[derive(Deserialize)]
struct Settings {
    /// Either the shared secret itself or a whole `otpauth://` url, which the core tells apart
    secret_or_url: String,
    period: Option<u64>,
    digits: Option<usize>,
    hash_algorithm: Option<Algorithm>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<Algorithm> for OtpAlgorithm {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha1 => OtpAlgorithm::SHA1,
            Algorithm::Sha256 => OtpAlgorithm::SHA256,
            Algorithm::Sha512 => OtpAlgorithm::SHA512,
        }
    }
}

impl From<Settings> for OtpSettings {
    fn from(settings: Settings) -> Self {
        OtpSettings {
            secret_or_url: settings.secret_or_url,
            period: settings.period,
            digits: settings.digits,
            hash_algorithm: settings.hash_algorithm.map(Into::into),
        }
    }
}

#[derive(Serialize)]
struct OtpUrl {
    otp_url: String,
}

#[derive(Serialize)]
struct UrlValidity {
    valid: bool,
}

/// The current token of every entry asked for that has 2fa. Entries without it are simply absent.
pub(crate) fn entry_list_current_otps(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::EntryListCurrentOtps, input)?;
    let args: CurrentOtpsArgs = args(args_json)?;

    let tokens = db_service::entry_list_current_otps(&args.db_key, &args.entry_uuids)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&tokens)
}

/// Builds the `otpauth://` url out of the settings - what a "show the qr code" screen needs. No
/// database is involved.
pub(crate) fn form_otp_url(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::FormOtpUrl, input)?;
    let settings: Settings = args(args_json)?;

    let url = db_service::form_otp_url(&settings.into()).map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&OtpUrl { otp_url: url })
}

/// Whether a scanned or pasted url is one the core can read. A plain answer, not a failure: the ui
/// asks this while the user is still typing.
pub(crate) fn is_valid_otp_url(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::IsValidOtpUrl, input)?;
    let args: OtpUrlArgs = args(args_json)?;

    json_answer(&UrlValidity {
        valid: db_service::is_valid_otp_url(&args.otp_url),
    })
}

/// Sets or replaces the 2fa of an entry. The core validates the settings first, so a secret that
/// cannot be decoded comes back as a failure and the entry is left alone.
pub(crate) fn set_entry_otp(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::SetEntryOtp, input)?;
    let args: EntryOtpArgs = args(args_json)?;

    db_service::set_entry_otp(&args.db_key, &args.entry_uuid, &args.settings.into())
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Removes the 2fa of an entry, whichever format it was stored in.
pub(crate) fn delete_entry_otp(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DeleteEntryOtp, input)?;
    let args: EntryIdArgs = args(args_json)?;

    db_service::delete_entry_otp(&args.db_key, &args.entry_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}
