// No unsafe in this crate. forbid (not deny) cannot be overridden by a local #[allow],
// so unsafe coming back through our code or a macro expanded here fails the build
#![forbid(unsafe_code)]

// pub mod callback_service;

mod constants;
mod crypto;
pub mod custom_icons;

mod db;
mod db_merge;
mod form_data;

mod password_generator;
mod redacted;
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
