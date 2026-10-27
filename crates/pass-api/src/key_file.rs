//! A key file as it crosses the boundary: its name and its content, base64 inside the json arguments.
//!
//! Why not the binary slot of the frame, as the database travels: `read_kdbx` already fills it with the
//! database, and a second slot would mean another jni signature and another frame format for one
//! command. The password travels in the json too, so the key file sits at the same level - and the
//! arguments are wiped after the call (`lib.rs`), base64 included. A key file of our own is about 250
//! bytes; any file can be a key, though, so the size is checked before anything is decoded.
//!
//! Why not a path, as the core used to take: on Android a key file is behind SAF and has no path the
//! core could open. A path into the app's own storage would mean a copy there, and that directory goes
//! with a reinstall - the key and with it the database (Step 29 in pass-docs).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use zeroize::Zeroize;

use kdbx_rust_core::db_service::{Error, FileKey, KEY_FILE_MAX_SIZE};

use crate::errors::ErrorPayload;

#[derive(Deserialize)]
pub(crate) struct KeyFileArg {
    /// The name to show back - the display name from SAF, not a path
    name: String,
    /// The whole file, base64 (standard alphabet, padded)
    content: String,
}

impl KeyFileArg {
    pub(crate) fn into_file_key(self) -> Result<FileKey, ErrorPayload> {
        // base64 is 4 characters per 3 bytes: a longer text cannot decode to a file within the limit,
        // and refusing it here keeps a picked video from being decoded at all
        if self.content.len() as u64 > KEY_FILE_MAX_SIZE.div_ceil(3) * 4 {
            return Err(ErrorPayload::of(&Error::KeyFileTooLarge));
        }

        let mut content = STANDARD.decode(self.content.as_bytes()).map_err(|e| {
            ErrorPayload::bridge(
                "InvalidArguments",
                format!("The key file is not valid base64: {}", e),
            )
        })?;

        let file_key = FileKey::from_bytes(&self.name, &content).map_err(|e| ErrorPayload::of(&e));
        content.zeroize();
        file_key
    }
}

/// The key file of a call, if there is one.
pub(crate) fn file_key_of(arg: Option<KeyFileArg>) -> Result<Option<FileKey>, ErrorPayload> {
    arg.map(KeyFileArg::into_file_key).transpose()
}

/// The content of a key file in the form `KeyFileArg` takes it - for the tests, which build the json
/// the way Kotlin does.
#[cfg(test)]
pub(crate) fn encode(content: &[u8]) -> String {
    STANDARD.encode(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arg(content: String) -> KeyFileArg {
        KeyFileArg {
            name: "key.keyx".into(),
            content,
        }
    }

    #[test]
    fn a_key_file_comes_back_with_its_name() {
        let key = arg(encode(b"any bytes")).into_file_key().ok().unwrap();
        assert_eq!(key.file_name(), "key.keyx");
    }

    #[test]
    fn text_that_is_not_base64_is_refused_as_arguments() {
        let refused = arg("not base64 !".into()).into_file_key().err().unwrap();
        assert_eq!(refused.kind, "InvalidArguments");
    }

    #[test]
    fn a_key_file_of_the_limit_is_accepted() {
        let content = vec![0u8; KEY_FILE_MAX_SIZE as usize];
        assert!(arg(encode(&content)).into_file_key().is_ok());
    }

    #[test]
    fn a_key_file_over_the_limit_is_refused_with_its_own_kind() {
        let content = vec![0u8; KEY_FILE_MAX_SIZE as usize + 1];
        let refused = arg(encode(&content)).into_file_key().err().unwrap();
        assert_eq!(refused.kind, "KeyFileTooLarge");
    }

    #[test]
    fn text_too_long_to_be_a_key_file_is_refused_before_decoding() {
        // Not base64 at all: had it been decoded, the kind would be InvalidArguments
        let too_long = "!".repeat((KEY_FILE_MAX_SIZE.div_ceil(3) * 4) as usize + 1);
        let refused = arg(too_long).into_file_key().err().unwrap();
        assert_eq!(refused.kind, "KeyFileTooLarge");
    }
}
