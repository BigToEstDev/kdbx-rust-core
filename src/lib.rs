// No unsafe in this crate. forbid (not deny) cannot be overridden by a local #[allow],
// so unsafe coming back through our code or a macro expanded here fails the build
#![forbid(unsafe_code)]

// pub mod callback_service;

// Csv import (upstream code, 10 exporter profiles) is parked behind the default-off feature
// `csv-import`: it is not part of v1 and is not exposed through the FFI. Step 20 p.2 -- the module
// never passed our own audit (unlike the file-reading path hardened in Step 17-19) and it still
// needs work before it can ship: reading from a stream instead of a path, no global state between
// steps, the ignored parser options bug, BOM / encodings, an import report. Kept compiled and
// tested (the test build turns the feature on) so it does not rot until then; the plan for import
// formats is plan/todo/core/import-formats.md in pass-docs. Requires a desktop target for now:
// creating a database from csv goes through the desktop-only write_new_db_kdbx_file.
#[cfg(feature = "csv-import")]
mod import;

mod constants;
mod crypto;
pub mod custom_icons;

mod db;
mod db_merge;
mod form_data;

mod password_generator;
mod searcher;
mod xml_parse;

pub mod async_service;
pub mod db_content;
pub mod db_service;
pub mod error;
pub mod util;

pub use crate::util as service_util;

extern crate lazy_static;
extern crate log;
