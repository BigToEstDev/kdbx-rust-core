// pub mod callback_service;

// For now import feature is supported only in desktop app
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
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

#[macro_use]
extern crate slice_as_array;
extern crate lazy_static;
extern crate log;
