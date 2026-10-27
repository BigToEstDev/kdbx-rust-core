//! The envelope every call returns.
//!
//! A failing operation is not an exception: opening a database with the wrong password, or a name that
//! is already taken, are ordinary outcomes the ui has to show. They travel as data:
//!
//! ```json
//! {"ok":  {"password": "..."}}
//! {"err": {"kind": "NotFound", "message": "No entry found for the id"}}
//! ```
//!
//! `kind` lets the app branch on the failure without parsing prose, `message` is for the log and for
//! the cases where the ui has nothing better to show. An exception is thrown only when the bridge
//! itself is broken - a panic, or json that cannot be built - because that is a bug, not an outcome.

use serde::Serialize;

use kdbx_rust_core::error::Error;

#[derive(Serialize, Debug)]
pub(crate) struct ErrorPayload {
    /// The name of the core's error variant, e.g. `NotFound`, `DbKeyNotFound`, `Io`
    pub(crate) kind: String,
    pub(crate) message: String,
}

impl ErrorPayload {
    pub(crate) fn of(error: &Error) -> Self {
        ErrorPayload {
            kind: error_kind(error),
            message: error.to_string(),
        }
    }

    pub(crate) fn bridge(kind: &str, message: impl Into<String>) -> Self {
        ErrorPayload {
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

// The core's Error is a #[non_exhaustive] enum that does not implement Serialize, and
// matching all of them here would go stale on every new variant. Debug already prints the variant
// name first (`NotFound("...")`, `DbKeyNotFound`), so the name is taken from there: everything up to
// the first delimiter. A variant rename therefore changes `kind` - that is intended, it is the same
// contract break as renaming a json field, and Step 23 covers it with contract tests.
//
// There used to be one exception, `AlreadyExists` out of `Io`, for a key file written over an existing
// one. Since Step 29 the core hands the key file back as bytes and nothing behind this boundary writes a
// file, so every io failure is `Io` again.
fn error_kind(error: &Error) -> String {
    let debug = format!("{:?}", error);
    let name = debug
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|part| !part.is_empty())
        .unwrap_or("Unknown");
    name.to_string()
}

/// Serialises a successful result into the `ok` envelope.
pub(crate) fn ok_envelope<T: Serialize>(value: &T) -> Result<String, ErrorPayload> {
    #[derive(Serialize)]
    struct Ok<'a, T: Serialize> {
        ok: &'a T,
    }

    serde_json::to_string(&Ok { ok: value })
        .map_err(|e| ErrorPayload::bridge("ResponseSerialization", e.to_string()))
}

/// Serialises a failure into the `err` envelope. Falls back to a hand written json, because the
/// envelope has to reach Kotlin even if serialisation of the payload itself fails.
pub(crate) fn err_envelope(payload: &ErrorPayload) -> String {
    #[derive(Serialize)]
    struct Err<'a> {
        err: &'a ErrorPayload,
    }

    serde_json::to_string(&Err { err: payload }).unwrap_or_else(|_| {
        r#"{"err":{"kind":"ResponseSerialization","message":"the error itself could not be serialised"}}"#
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::{err_envelope, error_kind, ok_envelope, ErrorPayload};
    use kdbx_rust_core::error::Error;

    #[test]
    fn a_unit_variant_gives_its_own_name_as_the_kind() {
        assert_eq!(error_kind(&Error::DbKeyNotFound), "DbKeyNotFound");
    }

    #[test]
    fn a_variant_with_data_gives_the_name_without_the_data() {
        let error = Error::NotFound("no entry for that id".into());
        assert_eq!(error_kind(&error), "NotFound");
    }

    #[test]
    fn an_error_carries_both_the_kind_and_the_message() {
        let payload = ErrorPayload::of(&Error::NotFound("nothing here".into()));
        assert_eq!(payload.kind, "NotFound");
        assert_eq!(payload.message, "nothing here");

        let json = err_envelope(&payload);
        assert!(json.contains(r#""kind":"NotFound""#), "{}", json);
        assert!(json.contains(r#""message":"nothing here""#), "{}", json);
    }

    // Io stays Io: there the ui has nothing to offer but the message
    #[test]
    fn io_failures_keep_the_name_of_the_variant() {
        let error = Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "not allowed",
        ));

        assert_eq!(error_kind(&error), "Io");
    }

    #[test]
    fn a_result_is_wrapped_in_the_ok_envelope() {
        let json = ok_envelope(&"secret").unwrap();
        assert_eq!(json, r#"{"ok":"secret"}"#);
    }
}
