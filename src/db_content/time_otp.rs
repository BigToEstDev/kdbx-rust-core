// TOTP as the original KeePass 2.47+ writes it: four plain string fields of an entry instead of
// the single `otpauth://` url used by KeePassXC / KeePassDX (and by us). Only the mapping
// "entry fields -> OtpSettings" lives here; the codes themselves are computed by otp.rs.
//
// Step 21. There was no real KeePass to export a reference database from, so the field names and
// values follow the documented format, and the fixture is generated with pykeepass: it proves our
// own roundtrip, not compatibility with KeePass itself. To keep that assumption from costing the
// user their 2FA, the readers below are deliberately tolerant - every documented secret encoding is
// accepted, and the algorithm is recognised both as a bare name (`HMAC-SHA-256`) and as the
// XML-dsig uri KeePass may store (`http://www.w3.org/2001/04/xmldsig-more#hmac-sha256`).

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use data_encoding::BASE32_NOPAD;
use zeroize::Zeroize;

use crate::{
    constants::entry_keyvalue_key::{
        TIME_OTP_ALGORITHM, TIME_OTP_LENGTH, TIME_OTP_PERIOD, TIME_OTP_SECRET,
        TIME_OTP_SECRET_BASE32, TIME_OTP_SECRET_BASE64, TIME_OTP_SECRET_HEX,
    },
    db_content::{
        entry::{EntryField, KeyValue},
        entry_type::FieldDataType,
        otp::{OtpAlgorithm, OtpData, OtpSettings},
    },
    error::{Error, Result},
    util::strip_spaces,
};

// How the secret is encoded in the field that carries it
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum SecretEncoding {
    // The secret as typed: the bytes of the text itself
    Plain,
    Hex,
    Base32,
    Base64,
}

// The KeePass defaults, used when a field is absent and left out again when writing
const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_DIGITS: usize = 6;

// Secret fields in the order they are looked at. Base32 first: it is what an authenticator shows,
// what our own writer produces and what KeePassXC uses, so it is the likeliest to be the one the
// user means when an entry carries more than one secret field
const SECRET_FIELDS: [(&str, SecretEncoding); 4] = [
    (TIME_OTP_SECRET_BASE32, SecretEncoding::Base32),
    (TIME_OTP_SECRET_HEX, SecretEncoding::Hex),
    (TIME_OTP_SECRET_BASE64, SecretEncoding::Base64),
    (TIME_OTP_SECRET, SecretEncoding::Plain),
];

impl SecretEncoding {
    fn decode(&self, value: &str) -> Result<Vec<u8>> {
        let decoded = match self {
            // Taken as typed - spaces and case may be part of the secret
            SecretEncoding::Plain => value.as_bytes().to_vec(),
            SecretEncoding::Hex => hex::decode(strip_spaces(value)).map_err(|e| {
                Error::OtpKeyDecodeError(format!("Hex secret decoding failed with error {}", e))
            })?,
            // Base32 secrets are written in groups of characters and in either case
            SecretEncoding::Base32 => BASE32_NOPAD
                .decode(strip_spaces(value).to_uppercase().as_bytes())
                .map_err(|e| {
                    Error::OtpKeyDecodeError(format!(
                        "Base32 secret decoding failed with error {}",
                        e
                    ))
                })?,
            SecretEncoding::Base64 => STANDARD.decode(strip_spaces(value)).map_err(|e| {
                Error::OtpKeyDecodeError(format!("Base64 secret decoding failed with error {}", e))
            })?,
        };

        if decoded.is_empty() {
            return Err(Error::OtpKeyDecodeError(
                "The TimeOtp secret field is empty".into(),
            ));
        }

        Ok(decoded)
    }

    // Used when writing a secret back into the field it came from
    pub(crate) fn encode(&self, decoded_secret: &[u8]) -> Result<String> {
        match self {
            SecretEncoding::Plain => String::from_utf8(decoded_secret.to_vec()).map_err(|_| {
                Error::UnexpectedError(
                    "The secret is not text and cannot be written as a plain TimeOtp secret".into(),
                )
            }),
            SecretEncoding::Hex => Ok(hex::encode(decoded_secret)),
            SecretEncoding::Base32 => Ok(BASE32_NOPAD.encode(decoded_secret)),
            SecretEncoding::Base64 => Ok(STANDARD.encode(decoded_secret)),
        }
    }
}

// The TimeOtp fields of one entry, ready to be turned into a token by otp.rs
#[derive(Debug)]
pub(crate) struct TimeOtp {
    // The field the secret was read from: the entry's otp token is keyed by this name, exactly as
    // an `otpauth://` field is keyed by its own name
    pub(crate) secret_field: &'static str,

    // The secret is carried as Base32 here: that is what OtpData::from_key expects
    pub(crate) settings: OtpSettings,
}

// Writes a totp back into the TimeOtp fields of an entry, in the encoding the entry already used.
//
// Only the fields KeePass needs are kept: a period, a length or an algorithm equal to the KeePass
// default is removed rather than written, which is how KeePass itself stores them. Any other secret
// field is removed as well - an entry left holding a second, now stale secret would both contradict
// itself (which code is the real one?) and keep an old plaintext secret in the file.
pub(crate) fn write(
    entry_field: &mut EntryField,
    otp_data: &OtpData,
    encoding: SecretEncoding,
) -> Result<()> {
    let secret_field = SECRET_FIELDS
        .iter()
        .find(|(_, e)| *e == encoding)
        .map(|(name, _)| *name)
        // Every encoding has a field, so this cannot happen
        .ok_or_else(|| Error::UnexpectedError("Unknown TimeOtp secret encoding".into()))?;

    let secret = encoding.encode(&otp_data.decoded_secret)?;

    for (name, _) in SECRET_FIELDS
        .iter()
        .filter(|(name, _)| *name != secret_field)
    {
        entry_field.remove_key_value(name);
    }
    set_field(entry_field, secret_field, &secret, true);

    set_or_remove(
        entry_field,
        TIME_OTP_PERIOD,
        (otp_data.period != DEFAULT_PERIOD).then(|| otp_data.period.to_string()),
    );
    set_or_remove(
        entry_field,
        TIME_OTP_LENGTH,
        (otp_data.digits != DEFAULT_DIGITS).then(|| otp_data.digits.to_string()),
    );
    set_or_remove(
        entry_field,
        TIME_OTP_ALGORITHM,
        algorithm_value(entry_field, otp_data.algorithm),
    );

    Ok(())
}

// Removes every TimeOtp field of an entry, so deleting a 2fa leaves no tail behind
pub(crate) fn remove_all(entry_field: &mut EntryField) {
    for (name, _) in SECRET_FIELDS.iter() {
        entry_field.remove_key_value(name);
    }
    for name in [TIME_OTP_PERIOD, TIME_OTP_LENGTH, TIME_OTP_ALGORITHM] {
        entry_field.remove_key_value(name);
    }
}

// Keeps the spelling the file already used when it means the same algorithm - a uri stays a uri -
// and writes a bare name otherwise. SHA1 is the KeePass default and needs no field
fn algorithm_value(entry_field: &EntryField, algorithm: OtpAlgorithm) -> Option<String> {
    if algorithm == OtpAlgorithm::SHA1 {
        return None;
    }

    if let Some(kv) = entry_field.find_key_value(TIME_OTP_ALGORITHM) {
        if algorithm_of(&kv.value).ok() == Some(Some(algorithm)) {
            return Some(kv.value.clone());
        }
    }

    Some(
        match algorithm {
            OtpAlgorithm::SHA1 => "HMAC-SHA-1",
            OtpAlgorithm::SHA256 => "HMAC-SHA-256",
            OtpAlgorithm::SHA512 => "HMAC-SHA-512",
        }
        .to_string(),
    )
}

fn set_or_remove(entry_field: &mut EntryField, field_name: &str, value: Option<String>) {
    match value {
        Some(v) => set_field(entry_field, field_name, &v, false),
        None => {
            entry_field.remove_key_value(field_name);
        }
    }
}

// Updates the field in place when the entry already has it, keeping its protection flag as the file
// had it, and adds it otherwise
fn set_field(entry_field: &mut EntryField, field_name: &str, value: &str, protect_when_new: bool) {
    if entry_field.find_key_value(field_name).is_some() {
        entry_field.update_value(field_name, value);
    } else {
        entry_field.insert_key_value(KeyValue {
            key: field_name.to_string(),
            value: value.to_string(),
            protected: protect_when_new,
            data_type: FieldDataType::default(),
        });
    }
}

// Reads the TimeOtp fields of an entry.
//
// None means the entry has no TimeOtp secret field at all - the usual case, nothing to report.
// Some(Err) means it has one but it cannot be used (undecodable secret, a period or a length
// outside what the core supports, an unknown algorithm); the caller decides what to do with it,
// and nothing about the entry's fields is changed either way.
pub(crate) fn parse(field_values: &HashMap<String, String>) -> Option<Result<TimeOtp>> {
    let (secret_field, encoding) = secret_field_of(field_values)?;

    // The key was just matched above, so the value is there
    let raw_secret = field_values.get(secret_field)?;

    Some(build(secret_field, encoding, raw_secret, field_values))
}

// The secret field an entry carries and its encoding, whether or not the fields can be used: an
// update has to be written in the entry's own form even when the old value was unreadable
pub(crate) fn secret_encoding(field_values: &HashMap<String, String>) -> Option<SecretEncoding> {
    secret_field_of(field_values).map(|(_, encoding)| encoding)
}

fn secret_field_of(
    field_values: &HashMap<String, String>,
) -> Option<(&'static str, SecretEncoding)> {
    SECRET_FIELDS
        .iter()
        .find(|(name, _)| field_values.contains_key(*name))
        .map(|(name, encoding)| (*name, *encoding))
}

fn build(
    secret_field: &'static str,
    encoding: SecretEncoding,
    raw_secret: &str,
    field_values: &HashMap<String, String>,
) -> Result<TimeOtp> {
    let mut decoded_secret = encoding.decode(raw_secret)?;
    // The secret lives on inside OtpSettings as Base32; this copy of the raw bytes does not
    let base32_secret = BASE32_NOPAD.encode(&decoded_secret);
    decoded_secret.zeroize();

    let settings = OtpSettings {
        secret_or_url: base32_secret,
        period: number_field(field_values, TIME_OTP_PERIOD)?,
        digits: number_field(field_values, TIME_OTP_LENGTH)?,
        hash_algorithm: algorithm_field(field_values)?,
    };

    Ok(TimeOtp {
        secret_field,
        settings,
    })
}

// An absent field means the KeePass default, which is also what OtpSettings uses for None:
// period 30 seconds, length 6 digits, SHA1. An unreadable value is an error rather than a silent
// fallback to the default - a code generated from a wrong period is worse than no code
fn number_field<T: std::str::FromStr>(
    field_values: &HashMap<String, String>,
    field_name: &str,
) -> Result<Option<T>> {
    match field_values.get(field_name) {
        None => Ok(None),
        Some(value) => match value.trim().parse::<T>() {
            Ok(parsed) => Ok(Some(parsed)),
            Err(_) => Err(Error::UnexpectedError(format!(
                "The field {} holds '{}', which is not a number",
                field_name, value
            ))),
        },
    }
}

fn algorithm_field(field_values: &HashMap<String, String>) -> Result<Option<OtpAlgorithm>> {
    let Some(value) = field_values.get(TIME_OTP_ALGORITHM) else {
        return Ok(None);
    };

    algorithm_of(value)
}

fn algorithm_of(value: &str) -> Result<Option<OtpAlgorithm>> {
    // A uri keeps the algorithm in its fragment (xmldsig#hmac-sha256); a bare name is the whole
    // value. Separators vary in spelling (HMAC-SHA-256, hmac_sha256), so they are dropped
    let tail = value.rsplit(['#', '/']).next().unwrap_or(value);
    let normalised = tail
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase();

    match normalised.as_str() {
        "sha1" | "hmacsha1" => Ok(Some(OtpAlgorithm::SHA1)),
        "sha256" | "hmacsha256" => Ok(Some(OtpAlgorithm::SHA256)),
        "sha512" | "hmacsha512" => Ok(Some(OtpAlgorithm::SHA512)),
        _ => Err(Error::UnexpectedError(format!(
            "The hash algorithm '{}' of the field {} is not supported",
            value, TIME_OTP_ALGORITHM
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{parse, SecretEncoding};
    use crate::constants::entry_keyvalue_key::{
        TIME_OTP_ALGORITHM, TIME_OTP_LENGTH, TIME_OTP_PERIOD, TIME_OTP_SECRET,
        TIME_OTP_SECRET_BASE32, TIME_OTP_SECRET_BASE64, TIME_OTP_SECRET_HEX,
    };
    use crate::db_content::otp::OtpAlgorithm;

    // The RFC 6238 test secret "12345678901234567890" in each encoding KeePass may use
    const SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SECRET_HEX: &str = "3132333435363738393031323334353637383930";
    const SECRET_BASE64: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";
    const SECRET_PLAIN: &str = "12345678901234567890";

    fn fields(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn an_entry_without_a_secret_field_is_not_a_time_otp_entry() {
        assert!(parse(&fields(&[
            ("Title", "My Bank"),
            ("otp", "otpauth://totp/x")
        ]))
        .is_none());
    }

    #[test]
    fn every_documented_secret_encoding_yields_the_same_secret() {
        for (field, value) in [
            (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
            (TIME_OTP_SECRET_HEX, SECRET_HEX),
            (TIME_OTP_SECRET_BASE64, SECRET_BASE64),
            (TIME_OTP_SECRET, SECRET_PLAIN),
        ] {
            let parsed = parse(&fields(&[(field, value)]))
                .expect("a secret field is present")
                .unwrap_or_else(|e| panic!("{} was not read: {}", field, e));

            assert_eq!(parsed.secret_field, field);
            assert_eq!(
                parsed.settings.secret_or_url, SECRET_BASE32,
                "{} decoded to a different secret",
                field
            );
        }
    }

    #[test]
    fn a_spaced_and_lowercase_base32_secret_is_accepted() {
        // How an authenticator shows a secret, and how a user may paste it
        let parsed = parse(&fields(&[(
            TIME_OTP_SECRET_BASE32,
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
        )]))
        .unwrap()
        .unwrap();
        assert_eq!(parsed.settings.secret_or_url, SECRET_BASE32);
    }

    #[test]
    fn absent_optional_fields_leave_the_keepass_defaults() {
        let parsed = parse(&fields(&[(TIME_OTP_SECRET_BASE32, SECRET_BASE32)]))
            .unwrap()
            .unwrap();
        assert!(parsed.settings.period.is_none());
        assert!(parsed.settings.digits.is_none());
        assert!(parsed.settings.hash_algorithm.is_none());
    }

    #[test]
    fn period_and_length_are_read() {
        let parsed = parse(&fields(&[
            (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
            (TIME_OTP_PERIOD, "60"),
            (TIME_OTP_LENGTH, "8"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(parsed.settings.period, Some(60));
        assert_eq!(parsed.settings.digits, Some(8));
    }

    #[test]
    fn base32_wins_when_an_entry_carries_several_secret_fields() {
        let parsed = parse(&fields(&[
            (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
            (TIME_OTP_SECRET_HEX, "00"),
            (TIME_OTP_SECRET, "other"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(parsed.secret_field, TIME_OTP_SECRET_BASE32);
    }

    #[test]
    fn the_encoding_of_the_entrys_secret_field_is_reported_for_writing() {
        use super::secret_encoding;
        assert_eq!(
            secret_encoding(&fields(&[(TIME_OTP_SECRET_HEX, SECRET_HEX)])),
            Some(SecretEncoding::Hex)
        );
        // Reported even when the value itself is unusable: an update keeps the entry's own form
        assert_eq!(
            secret_encoding(&fields(&[(TIME_OTP_SECRET_BASE64, "###")])),
            Some(SecretEncoding::Base64)
        );
        assert_eq!(
            secret_encoding(&fields(&[("otp", "otpauth://totp/x")])),
            None
        );
    }

    #[test]
    fn hex_is_used_when_there_is_no_base32_field() {
        let parsed = parse(&fields(&[
            (TIME_OTP_SECRET_HEX, SECRET_HEX),
            (TIME_OTP_SECRET, "other"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(parsed.secret_field, TIME_OTP_SECRET_HEX);
        assert_eq!(parsed.settings.secret_or_url, SECRET_BASE32);
    }

    #[test]
    fn an_algorithm_is_recognised_as_a_bare_name_and_as_a_uri() {
        for (value, expected) in [
            ("HMAC-SHA-1", OtpAlgorithm::SHA1),
            ("hmac_sha256", OtpAlgorithm::SHA256),
            ("SHA512", OtpAlgorithm::SHA512),
            (
                "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
                OtpAlgorithm::SHA1,
            ),
            (
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                OtpAlgorithm::SHA256,
            ),
            (
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
                OtpAlgorithm::SHA512,
            ),
        ] {
            let parsed = parse(&fields(&[
                (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
                (TIME_OTP_ALGORITHM, value),
            ]))
            .unwrap()
            .unwrap_or_else(|e| panic!("{} was not recognised: {}", value, e));
            assert_eq!(parsed.settings.hash_algorithm, Some(expected), "{}", value);
        }
    }

    #[test]
    fn an_unknown_algorithm_is_an_error_and_not_a_silent_fallback_to_sha1() {
        let r = parse(&fields(&[
            (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
            (TIME_OTP_ALGORITHM, "HMAC-SHA3-256"),
        ]))
        .unwrap();
        assert!(r.is_err(), "an unsupported algorithm must not be ignored");
    }

    #[test]
    fn an_undecodable_secret_is_an_error() {
        for (field, value) in [
            (TIME_OTP_SECRET_BASE32, "not base32 !!"),
            (TIME_OTP_SECRET_HEX, "zz"),
            (TIME_OTP_SECRET_BASE64, "###"),
        ] {
            let r = parse(&fields(&[(field, value)])).unwrap();
            assert!(r.is_err(), "{} with '{}' must not be used", field, value);
        }
    }

    #[test]
    fn an_empty_secret_field_is_an_error() {
        for field in [
            TIME_OTP_SECRET_BASE32,
            TIME_OTP_SECRET_HEX,
            TIME_OTP_SECRET_BASE64,
            TIME_OTP_SECRET,
        ] {
            let r = parse(&fields(&[(field, "")])).unwrap();
            assert!(r.is_err(), "{} holding nothing must not be used", field);
        }
    }

    #[test]
    fn a_non_numeric_period_or_length_is_an_error() {
        for field in [TIME_OTP_PERIOD, TIME_OTP_LENGTH] {
            let r = parse(&fields(&[
                (TIME_OTP_SECRET_BASE32, SECRET_BASE32),
                (field, "half a minute"),
            ]))
            .unwrap();
            assert!(r.is_err(), "{} must be a number", field);
        }
    }

    #[test]
    fn a_secret_is_encoded_back_into_the_form_it_came_in() {
        let secret = SECRET_PLAIN.as_bytes();
        assert_eq!(
            SecretEncoding::Base32.encode(secret).unwrap(),
            SECRET_BASE32
        );
        assert_eq!(SecretEncoding::Hex.encode(secret).unwrap(), SECRET_HEX);
        assert_eq!(
            SecretEncoding::Base64.encode(secret).unwrap(),
            SECRET_BASE64
        );
        assert_eq!(SecretEncoding::Plain.encode(secret).unwrap(), SECRET_PLAIN);
    }

    #[test]
    fn a_binary_secret_cannot_be_written_as_plain_text() {
        assert!(SecretEncoding::Plain.encode(&[0xff, 0xfe]).is_err());
    }
}
