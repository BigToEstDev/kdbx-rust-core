//! Entries: the list, the form behind one entry, and the operations that change it.
//!
//! An entry travels as the core's `EntryFormData` - the same reasoning as for a group. Its fields are
//! private and it exists only through serde, so its json *is* the shape, and `insert_entry_from_form_data`
//! and `update_entry_from_form_data` take the whole thing. The ui asks for a form, fills it in, and sends
//! it back.
//!
//! Two names of the core leak through it and stay in `:core:core-data` on the other side: the field
//! `group_uuid`, which means the parent group (a TODO of the upstream), and `EntryCategory`, which is
//! `camelCase` and externally tagged. The category is an *argument*, so it does not leak: this module
//! takes a snake_case tagged one and maps it, and the core's spelling never reaches Kotlin.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use kdbx_rust_core::db_service::{
    self, EntryCategory, EntryCloneOption, EntryFormData, NewAttachment,
};

use crate::commands::Command;
use crate::dispatch::Answer;
use crate::errors::ErrorPayload;
use crate::handlers::attachments::new_attachment_bytes;
use crate::handlers::{args, json_answer, reject_bytes, Done};

/// Arguments naming one entry of an open database.
#[derive(Deserialize)]
struct EntryIdArgs {
    db_key: String,
    entry_uuid: Uuid,
}

/// Arguments carrying a whole entry form - inserting a new entry, or updating an existing one.
#[derive(Deserialize)]
struct EntryFormArgs {
    db_key: String,
    form_data: EntryFormData,
    /// The files added with the form, their bytes in the slot of the call; absent - none
    #[serde(default)]
    new_attachments: Vec<NewAttachment>,
}

#[derive(Deserialize)]
struct EntrySummaryArgs {
    db_key: String,
    category: Category,
}

/// Arguments of `new_entry_form_data`: no database is needed - the blank form is the kdbx standard fields.
#[derive(Deserialize)]
struct NewEntryFormArgs {
    /// The group the entry is created in. Absent means the ui has not picked one yet
    parent_group_uuid: Option<Uuid>,
}

#[derive(Deserialize)]
struct MoveEntryArgs {
    db_key: String,
    entry_uuid: Uuid,
    /// The group it moves into
    new_parent_uuid: Uuid,
}

/// Arguments of `clone_entry`, flat rather than the core's nested `EntryCloneOption`: the options are
/// four plain answers of one dialog, and a nested object would only mirror a type the ui never sees.
#[derive(Deserialize)]
struct CloneEntryArgs {
    db_key: String,
    entry_uuid: Uuid,
    /// The title of the copy; absent keeps the title of the original
    new_title: Option<String>,
    /// The group the copy goes into - not necessarily the group of the original
    parent_group_uuid: Uuid,
    keep_histories: bool,
    /// The copy refers to the username and password of the original instead of holding its own
    link_by_reference: bool,
}

/// Which entries to list.
///
/// The core's own `EntryCategory` is `camelCase` and externally tagged (`{"group": "uuid"}`), which is
/// the one enum in the api that does not follow its own convention. Arguments are ours, so the wire
/// spells it snake_case and internally tagged - `{"kind": "all_entries"}`, `{"kind": "group", "value":
/// "…"}` - and the mapping lives here, in one place, instead of in every Kotlin model.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum Category {
    AllEntries,
    Favorites,
    Deleted,
    Group(String),
    Tag(String),
}

impl From<Category> for EntryCategory {
    fn from(category: Category) -> Self {
        match category {
            Category::AllEntries => EntryCategory::AllEntries,
            Category::Favorites => EntryCategory::Favorites,
            Category::Deleted => EntryCategory::Deleted,
            Category::Group(uuid) => EntryCategory::Group(uuid),
            Category::Tag(tag) => EntryCategory::Tag(tag),
        }
    }
}

/// The uuid of a freshly cloned entry.
#[derive(Serialize)]
struct ClonedEntry {
    entry_uuid: Uuid,
}

/// The entries of one category, with just enough of each to draw a row.
pub(crate) fn entry_summary_data(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::EntrySummaryData, input)?;
    let args: EntrySummaryArgs = args(args_json)?;

    let entries = db_service::entry_summary_data(&args.db_key, args.category.into())
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&entries)
}

/// One entry as a form: the preset fields, the entry's own fields, tags, times. Placeholders are
/// already resolved by the core.
pub(crate) fn get_entry_form_data_by_id(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::GetEntryFormDataById, input)?;
    let args: EntryIdArgs = args(args_json)?;

    let form = db_service::get_entry_form_data_by_id(&args.db_key, &args.entry_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&form)
}

/// The fields of an entry as a flat map, for the places that want a value by name rather than a form -
/// autofill, and copying a password out of a list.
pub(crate) fn entry_key_value_fields(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::EntryKeyValueFields, input)?;
    let args: EntryIdArgs = args(args_json)?;

    let fields = db_service::entry_key_value_fields(&args.db_key, &args.entry_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&fields)
}

/// An empty form with the kdbx standard fields - the app lays its preset over it for the "new entry"
/// screen.
pub(crate) fn new_entry_form_data(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::NewEntryFormData, input)?;
    let args: NewEntryFormArgs = args(args_json)?;

    let form = db_service::new_entry_form_data(args.parent_group_uuid.as_ref());

    json_answer(&form)
}

/// Puts a filled in form into the database as a new entry, with its new attachments - see `attachments`.
pub(crate) fn insert_entry_from_form_data(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    // The new attachments are plaintext: wiped whatever is refused below
    let input = input.map(Zeroizing::new);
    let args: EntryFormArgs = args(args_json)?;
    let bytes = new_attachment_bytes(
        Command::InsertEntryFromFormData,
        &args.new_attachments,
        input,
    )?;

    db_service::insert_entry_from_form_data_with_attachments(
        &args.db_key,
        args.form_data,
        &args.new_attachments,
        bytes,
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Writes an edited form back, with its new attachments - see `attachments`. The core keeps the previous version in
/// the history of the entry.
pub(crate) fn update_entry_from_form_data(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    let input = input.map(Zeroizing::new);
    let args: EntryFormArgs = args(args_json)?;
    let bytes = new_attachment_bytes(
        Command::UpdateEntryFromFormData,
        &args.new_attachments,
        input,
    )?;

    db_service::update_entry_from_form_data_with_attachments(
        &args.db_key,
        args.form_data,
        &args.new_attachments,
        bytes,
    )
    .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Moves an entry into another group.
pub(crate) fn move_entry(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::MoveEntry, input)?;
    let args: MoveEntryArgs = args(args_json)?;

    db_service::move_entry(&args.db_key, args.entry_uuid, args.new_parent_uuid)
        .map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}

/// Copies an entry, and answers with the uuid of the copy.
pub(crate) fn clone_entry(args_json: &str, input: Option<Vec<u8>>) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::CloneEntry, input)?;
    let args: CloneEntryArgs = args(args_json)?;

    let option = EntryCloneOption {
        new_title: args.new_title,
        parent_group_uuid: args.parent_group_uuid,
        keep_histories: args.keep_histories,
        link_by_reference: args.link_by_reference,
    };

    let entry_uuid = db_service::clone_entry(&args.db_key, &args.entry_uuid, &option)
        .map_err(|e| ErrorPayload::of(&e))?;

    json_answer(&ClonedEntry { entry_uuid })
}

/// The "delete" of the ui: into the recycle bin - reversible - or for good when the database does not
/// use a bin (`RecycleBinEnabled`); the core decides by the flag, the ui only words its warning by it.
pub(crate) fn delete_entry(
    args_json: &str,
    input: Option<Vec<u8>>,
) -> Result<Answer, ErrorPayload> {
    reject_bytes(Command::DeleteEntry, input)?;
    let args: EntryIdArgs = args(args_json)?;

    db_service::delete_entry(&args.db_key, args.entry_uuid).map_err(|e| ErrorPayload::of(&e))?;

    Done::answer()
}
