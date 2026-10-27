//! Name of a command -> the handler that answers it.
//!
//! Every call is `command` plus a json object of arguments, and the answer is the envelope from
//! `errors`. One function instead of a function per operation: the core's types already carry serde
//! derives, so json is the cheapest possible bridge, and adding an operation later touches this file
//! and one handler - not the platform layers (the jni bridge on android, the tauri commands on desktop).
//!
//! This file is the routing table and nothing else. The match is over the enum, so a command added to
//! `commands` without a branch here does not compile: the registry and the implementation cannot drift
//! apart. The work lives in `handlers`, a module per block of the api.

use crate::commands::Command;
use crate::errors::{err_envelope, ErrorPayload};
use crate::handlers::{
    entries, generator, groups, history, integrity, lifecycle, otp, search, settings, trash,
};

/// What a command answers: the envelope always, and raw bytes when the command produces a file - the
/// bytes of a database on save. Kept apart from the envelope on purpose, so a database never has to be
/// base64'd into json.
pub struct Answer {
    pub envelope: String,
    pub payload: Option<Vec<u8>>,
}

/// Runs one command and returns the json envelope. Never panics on bad input: unknown commands and
/// unparseable arguments come back as `err`.
pub fn run(command: &str, args_json: &str) -> String {
    run_with_bytes(command, args_json, None).envelope
}

/// The same, for the binary boundary: arguments may carry secrets and the command may be handed the
/// bytes of a database.
pub fn run_with_bytes(command: &str, args_json: &str, input: Option<Vec<u8>>) -> Answer {
    match dispatch(command, args_json, input) {
        Ok(answer) => answer,
        Err(payload) => Answer {
            envelope: err_envelope(&payload),
            payload: None,
        },
    }
}

fn dispatch(
    command: &str,
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let parsed = Command::parse(command).ok_or_else(|| {
        ErrorPayload::bridge(
            "UnknownCommand",
            format!("There is no command named '{}'", command),
        )
    })?;

    match parsed {
        Command::CreateAndWriteToWriter => lifecycle::create(args_json, input),
        Command::ReadKdbx => lifecycle::read(args_json, input),
        Command::SaveKdbxToWriter => lifecycle::save(args_json, input),
        Command::CloseKdbx => lifecycle::close(args_json, input),
        Command::LockKdbx => lifecycle::lock(args_json, input),
        Command::UnlockKdbx => lifecycle::unlock(args_json, input),
        Command::IsDbLocked => lifecycle::is_locked(args_json, input),
        Command::IsDbOpened => lifecycle::is_opened(args_json, input),
        Command::RenameDbKey => lifecycle::rename_db_key(args_json, input),
        Command::KdbxContextStatuses => lifecycle::context_statuses(args_json, input),
        Command::UnlockKdbxOnBiometricAuthentication => {
            lifecycle::unlock_on_biometric(args_json, input)
        }
        Command::VerifyPassword => lifecycle::verify_password(args_json, input),
        Command::CredentialsUsed => lifecycle::credentials_used(args_json, input),

        Command::GroupsSummaryData => groups::groups_summary_data(args_json, input),
        Command::GetGroupById => groups::get_group_by_id(args_json, input),
        Command::NewBlankGroup => groups::new_blank_group(args_json, input),
        Command::NewBlankGroupWithParent => groups::new_blank_group_with_parent(args_json, input),
        Command::InsertGroup => groups::insert_group(args_json, input),
        Command::UpdateGroup => groups::update_group(args_json, input),
        Command::MoveGroup => groups::move_group(args_json, input),
        Command::SortSubGroups => groups::sort_sub_groups(args_json, input),
        Command::CloneGroup => groups::clone_group(args_json, input),
        Command::DeleteGroup => groups::delete_group(args_json, input),

        Command::EntrySummaryData => entries::entry_summary_data(args_json, input),
        Command::GetEntryFormDataById => entries::get_entry_form_data_by_id(args_json, input),
        Command::EntryKeyValueFields => entries::entry_key_value_fields(args_json, input),
        Command::NewEntryFormData => entries::new_entry_form_data(args_json, input),
        Command::InsertEntryFromFormData => entries::insert_entry_from_form_data(args_json, input),
        Command::UpdateEntryFromFormData => entries::update_entry_from_form_data(args_json, input),
        Command::MoveEntry => entries::move_entry(args_json, input),
        Command::CloneEntry => entries::clone_entry(args_json, input),
        Command::DeleteEntry => entries::delete_entry(args_json, input),

        Command::HistoryEntriesSummary => history::history_entries_summary(args_json, input),
        Command::HistoryEntryByIndex => history::history_entry_by_index(args_json, input),
        Command::DeleteHistoryEntryByIndex => {
            history::delete_history_entry_by_index(args_json, input)
        }
        Command::DeleteHistoryEntries => history::delete_history_entries(args_json, input),

        Command::EntryListCurrentOtps => otp::entry_list_current_otps(args_json, input),
        Command::FormOtpUrl => otp::form_otp_url(args_json, input),
        Command::IsValidOtpUrl => otp::is_valid_otp_url(args_json, input),
        Command::SetEntryOtp => otp::set_entry_otp(args_json, input),
        Command::DeleteEntryOtp => otp::delete_entry_otp(args_json, input),

        Command::SearchTerm => search::search_term(args_json, input),
        Command::CollectEntryGroupTags => search::collect_entry_group_tags(args_json, input),

        Command::GetDbSettings => settings::get_db_settings(args_json, input),
        Command::SetDbSettings => settings::set_db_settings(args_json, input),
        Command::MeasureKdfPass => settings::measure_kdf_pass(args_json, input),
        Command::GenerateKeyFile => settings::generate_key_file(args_json, input),

        Command::VerifyDbFileChecksum => integrity::verify_db_file_checksum(args_json, input),
        Command::CalculateAndSetDbFileChecksum => {
            integrity::calculate_and_set_db_file_checksum(args_json, input)
        }
        Command::DbChecksumHash => integrity::db_checksum_hash(args_json, input),
        Command::MergeKdbxWithReader => integrity::merge_kdbx_with_reader(args_json, input),

        Command::TrashEntries => trash::trash_entries(args_json, input),
        Command::SearchTrash => trash::search_trash(args_json, input),
        Command::RestoreEntries => trash::restore_entries(args_json, input),
        Command::RemoveEntriesPermanently => trash::remove_entries_permanently(args_json, input),
        Command::EmptyTrash => trash::empty_trash(args_json, input),

        Command::GeneratePassword => generator::generate_password(args_json, input),
        Command::AnalyzedPassword => generator::analyzed_password(args_json, input),
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn a_command_answers_with_the_ok_envelope() {
        let json = run(
            "generate_password",
            r#"{"length":20,"numbers":true,"lowercase_letters":true,"uppercase_letters":true,"symbols":true,"spaces":false,"exclude_similar_characters":true,"strict":true}"#,
        );
        assert!(json.starts_with(r#"{"ok":{"password":""#), "{}", json);
        crate::contract::assert_shape("generate_password", &json);
    }

    #[test]
    fn empty_arguments_mean_the_defaults() {
        let json = run("generate_password", "");
        assert!(json.starts_with(r#"{"ok":{"password":""#), "{}", json);
    }

    #[test]
    fn an_unknown_command_is_an_error_and_not_a_panic() {
        let json = run("no_such_command", "{}");
        assert!(json.contains(r#""kind":"UnknownCommand""#), "{}", json);
    }

    #[test]
    fn bytes_sent_to_a_command_that_takes_none_are_refused() {
        let answer = super::run_with_bytes("generate_password", "", Some(vec![1, 2, 3]));
        assert!(
            answer.envelope.contains(r#""kind":"InvalidArguments""#),
            "{}",
            answer.envelope
        );
        assert!(answer.payload.is_none());
    }

    #[test]
    fn arguments_that_do_not_parse_are_reported_as_such() {
        let json = run("generate_password", "{not json");
        assert!(json.contains(r#""kind":"InvalidArguments""#), "{}", json);
    }

    // A length of zero is rejected by the core, and that rejection has to reach the caller as data
    #[test]
    fn a_failure_inside_the_core_keeps_its_own_kind() {
        let json = run(
            "generate_password",
            r#"{"length":0,"numbers":true,"lowercase_letters":true,"uppercase_letters":false,"symbols":false,"spaces":false,"exclude_similar_characters":false,"strict":false}"#,
        );
        assert!(json.starts_with(r#"{"err":"#), "{}", json);
        assert!(!json.contains("UnknownCommand"), "{}", json);
    }
}
