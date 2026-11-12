//! The api the apps call: a command name plus a json object of arguments in, the envelope from `errors`
//! out.
//!
//! Every platform layer sits on top of this crate and does nothing but carry strings and bytes across
//! its own boundary - the jni bridge on android (`pass-app/rust/pass-ffi`), the tauri commands on
//! desktop. What a command means, how its arguments are read and what its answer looks like is decided
//! here once, so the two apps cannot drift apart.
//!
//! Moved out of `pass-ffi` in Step 79: the platform independent part of the bridge, with its tests and
//! the contract files.

// No unsafe here either, like the core: the only unsafe code of the project is the jni layer
#![forbid(unsafe_code)]

use std::sync::Once;

/// The version of the core - of the workspace, the engine and this api share it (`Cargo.toml`). The apps show it
/// on their screen "About".
pub const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod attachment_tests;
mod commands;
#[cfg(test)]
mod contract;
mod dispatch;
#[cfg(test)]
mod entry_tests;
mod errors;
#[cfg(test)]
mod generator_tests;
#[cfg(test)]
mod group_tests;
mod handlers;
#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod integrity_tests;
mod key_file;
mod key_store;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod merge_tests;
#[cfg(test)]
mod otp_tests;
#[cfg(test)]
mod search_tests;
#[cfg(test)]
mod settings_tests;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod trash_tests;

pub use dispatch::{run, run_with_bytes, Answer};

static INIT: Once = Once::new();

/// One time setup: hands the core its key store. Safe to call from every entry point - only the first
/// call does anything. Logging is the platform's business and stays out of here.
pub fn init() {
    INIT.call_once(key_store::install);
}
