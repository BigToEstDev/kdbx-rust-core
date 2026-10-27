//! What the file of a database is, apart from its content: the version of the format and how the content is
//! packed before it is encrypted. Shown and changed on the settings screen of a database (pass-docs, Step 64).

use serde::{Deserialize, Serialize};

use crate::constants;
use crate::error::{Error, Result};

/// The version of KDBX the file was read as. The core reads 4.0 and 4.1 and always writes 4.1: a file read
/// as 4.0 becomes 4.1 with its first save. A database not read from a file is 4.1 - what it is written as.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdbxVersion {
    #[serde(rename = "4.0")]
    V40,
    #[default]
    #[serde(rename = "4.1")]
    V41,
}

impl KdbxVersion {
    /// The version of the signature of a file; None for one the core does not read.
    pub(crate) fn from_signature(version: u32) -> Option<Self> {
        match version {
            constants::VERSION_40 => Some(KdbxVersion::V40),
            constants::VERSION_41 => Some(KdbxVersion::V41),
            _ => None,
        }
    }
}

/// How the content of the file is packed before it is encrypted - the `CompressionFlags` field of the
/// header. GZip is what KeePass, KeePassXC and a new database of ours write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compression {
    #[default]
    None,
    GZip,
}

impl Compression {
    /// The compression of the flag of a header. A flag KDBX 4 does not have is a damaged header: read as
    /// "none", the content would fail later as xml that is not there, with a reason nobody could act on.
    pub(crate) fn from_flag(flag: i32) -> Result<Self> {
        match flag {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => Err(Error::HeaderCorrupted),
        }
    }

    /// The flag of the header for this compression.
    pub(crate) fn flag(self) -> i32 {
        match self {
            Compression::None => 0,
            Compression::GZip => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flags_of_kdbx_4_are_read_and_written_back() {
        for compression in [Compression::None, Compression::GZip] {
            assert_eq!(
                Compression::from_flag(compression.flag()).unwrap(),
                compression
            );
        }
    }

    #[test]
    fn an_unknown_flag_is_a_damaged_header() {
        for flag in [2, -1, i32::MAX] {
            assert!(matches!(
                Compression::from_flag(flag),
                Err(Error::HeaderCorrupted)
            ));
        }
    }

    #[test]
    fn only_the_versions_the_core_reads_have_a_version() {
        assert_eq!(
            KdbxVersion::from_signature(constants::VERSION_40),
            Some(KdbxVersion::V40)
        );
        assert_eq!(
            KdbxVersion::from_signature(constants::VERSION_41),
            Some(KdbxVersion::V41)
        );
        assert_eq!(KdbxVersion::from_signature(constants::VERSION_31), None);
    }

    #[test]
    fn the_versions_go_as_they_are_written() {
        assert_eq!(serde_json::to_string(&KdbxVersion::V40).unwrap(), "\"4.0\"");
        assert_eq!(serde_json::to_string(&KdbxVersion::V41).unwrap(), "\"4.1\"");
        assert_eq!(
            serde_json::to_string(&Compression::GZip).unwrap(),
            "\"GZip\""
        );
    }
}
