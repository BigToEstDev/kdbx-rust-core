//! `Debug` output for values that must never reach a log.
//!
//! A derived `Debug` prints every field, and one `debug!("{:?}", form)` is enough to put a master password
//! into logcat - release builds log `warn` and above, so not even a debug build is needed. Types that
//! carry a secret therefore write their `Debug` by hand and print the secret through this module:
//! `***` for the value, and for an `Option` only whether there is one.
//!
//! Hand-written rather than a `Secret<T>` wrapper type: a wrapper would change the model, serde and every
//! read of the field, for the same result in the logs. The wrapper, together with wiping on drop, is a
//! separate piece of work - see plan/todo/core/rust-core-bugs.md in pass-docs.

use std::fmt;

/// Stands in for a secret in `Debug` output.
pub(crate) struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

/// `Some(***)` or `None` - whether there is a secret, never what it is.
pub(crate) fn redacted_opt<T>(value: &Option<T>) -> Option<Redacted> {
    value.as_ref().map(|_| Redacted)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The assertion every type with a secret is tested with: its `Debug` output does not contain the
    /// secret, and does show that it was redacted.
    pub(crate) fn assert_hides(debug: &str, secret: &str) {
        assert!(
            !debug.contains(secret),
            "the secret is in the Debug output: {}",
            debug
        );
        assert!(debug.contains("***"), "nothing was redacted: {}", debug);
    }

    // --- The types with a secret, one test each. The ones whose fields are private to their module are
    // tested there: AnalyzedPassword, BasicEntryCredentialInfo, ImportedField, InnerHeader /
    // AttachmentSet (db/mod.rs). The public forms - NewDatabase, DbSettings, the fields of an entry
    // form - in tests/no_secrets_in_debug.rs, through the api

    const SECRET: &str = "s3cret-value";

    #[test]
    fn a_custom_data_item_hides_its_value() {
        // A passkey private key lives in custom data (KPEX_PASSKEY_PRIVATE_KEY_PEM)
        let item = crate::db_content::Item {
            key: "KPEX_PASSKEY_PRIVATE_KEY_PEM".into(),
            value: SECRET.into(),
            last_modification_time: None,
        };
        let debug = format!("{:?}", item);
        assert_hides(&debug, SECRET);
        assert!(debug.contains("KPEX_PASSKEY_PRIVATE_KEY_PEM"), "{}", debug);
    }

    #[test]
    fn an_entry_field_hides_its_value_protected_or_not() {
        for protected in [true, false] {
            let mut kv = crate::db_content::KeyValue::new();
            kv.key = "UserName".into();
            kv.value = SECRET.into();
            kv.protected = protected;
            let debug = format!("{:?}", kv);
            assert_hides(&debug, SECRET);
            assert!(
                debug.contains("UserName"),
                "the key stays visible: {}",
                debug
            );
        }
    }

    #[test]
    fn otp_types_hide_the_secret_and_the_current_code() {
        let settings = crate::db_content::OtpSettings {
            secret_or_url: SECRET.into(),
            period: Some(30),
            digits: Some(6),
            hash_algorithm: None,
        };
        assert_hides(&format!("{:?}", settings), SECRET);

        let token = crate::db_content::CurrentOtpTokenData {
            token: "492039".into(),
            ttl: 10,
            period: 30,
        };
        assert_hides(&format!("{:?}", token), "492039");

        // "Hello!" + 0xDEADBEEF; a Vec<u8> prints as decimals
        let data = crate::db_content::OtpData::from_key("JBSWY3DPEHPK3PXP").unwrap();
        assert_hides(&format!("{:?}", data), "72, 101, 108");
    }

    #[test]
    fn key_material_is_hidden() {
        let key_file = crate::db::KeyFileData::generate_key_data().unwrap();
        let data = key_file.data.clone().unwrap();
        assert_hides(&format!("{:?}", key_file), &data);

        let info = crate::db::SecureKeyInfo {
            key: vec![201, 202, 203],
            nonce: vec![211, 212, 213],
        };
        let debug = format!("{:?}", info);
        assert_hides(&debug, "201, 202, 203");
        assert_hides(&debug, "211, 212, 213");
    }

    #[test]
    fn a_secret_is_three_stars() {
        assert_eq!(format!("{:?}", Redacted), "***");
    }

    #[test]
    fn an_optional_secret_shows_only_whether_there_is_one() {
        assert_eq!(
            format!("{:?}", redacted_opt(&Some("pw".to_string()))),
            "Some(***)"
        );
        assert_eq!(format!("{:?}", redacted_opt::<String>(&None)), "None");
    }
}
