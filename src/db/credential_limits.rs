//! Limits on the credentials a database is closed with.
//!
//! Both are checked where the credentials enter the core, so every client gets the same answer. The app
//! repeats them in its own ui to refuse early - its constants must stay equal to these.

use crate::error::{Error, Result};

/// The largest key file accepted, in bytes.
///
/// KeePass takes any file as a key, and on the desktop that is often a photo of a few megabytes, so the
/// limit sits well above that: refusing someone's own key file would lock them out of their database.
/// What it stops is a video picked by mistake being read into memory whole.
pub const KEY_FILE_MAX_SIZE: u64 = 10 * 1024 * 1024;

/// The longest master password that can be set, in characters (Unicode scalar values, not bytes).
///
/// Checked only when a password is set - on creating a database and on changing the password. Never on
/// opening: KeePass has no such limit, and a database with a longer password must still open.
pub const PASSWORD_MAX_CHARS: usize = 256;

pub(crate) fn check_key_file_size(size: u64) -> Result<()> {
    if size > KEY_FILE_MAX_SIZE {
        return Err(Error::KeyFileTooLarge);
    }
    Ok(())
}

pub(crate) fn check_new_password(password: Option<&str>) -> Result<()> {
    match password {
        Some(p) if p.chars().count() > PASSWORD_MAX_CHARS => Err(Error::PasswordTooLong),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_of_the_limit_is_accepted() {
        assert!(check_key_file_size(KEY_FILE_MAX_SIZE).is_ok());
    }

    #[test]
    fn a_key_file_one_byte_over_the_limit_is_refused() {
        assert!(matches!(
            check_key_file_size(KEY_FILE_MAX_SIZE + 1),
            Err(Error::KeyFileTooLarge)
        ));
    }

    #[test]
    fn a_password_of_the_limit_is_accepted() {
        let password = "a".repeat(PASSWORD_MAX_CHARS);
        assert!(check_new_password(Some(&password)).is_ok());
    }

    #[test]
    fn a_password_one_char_over_the_limit_is_refused() {
        let password = "a".repeat(PASSWORD_MAX_CHARS + 1);
        assert!(matches!(
            check_new_password(Some(&password)),
            Err(Error::PasswordTooLong)
        ));
    }

    #[test]
    fn the_limit_counts_characters_not_bytes() {
        // Four bytes each in utf-8, two utf-16 units each in Kotlin - one character each here
        let password = "😀".repeat(PASSWORD_MAX_CHARS);
        assert!(check_new_password(Some(&password)).is_ok());
    }

    #[test]
    fn no_password_is_not_a_long_one() {
        assert!(check_new_password(None).is_ok());
    }
}
