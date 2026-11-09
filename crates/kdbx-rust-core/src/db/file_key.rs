use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use log::debug;

use crate::{
    crypto,
    error::{Error, Result},
    util,
    xml_parse::{FileKeyXmlReader, FileKeyXmlWriter},
};

/// A key file of exactly this many bytes is the key itself, not hashed (KeePass, KeePassXC)
const RAW_KEY_LEN: usize = 32;
/// A key file of exactly this many hex characters is the key hex encoded
const HEX_KEY_LEN: usize = 64;

use super::credential_limits::check_key_file_size;

/// Used when user selects to use any file as a key for the db
///
/// Built from the content of the file, never holds it: what the core needs is only the hash. The
/// content comes either from a path (desktop) or as bytes (mobile, where the file is behind SAF and has
/// no path the core could open).
#[derive(Clone)]
pub struct FileKey {
    // A path on desktop, a name to show on mobile - in both cases not what identifies the key,
    // the hash does
    pub(crate) file_name: String,
    // This is the hash of the whole content of a file or hash key from a keyx file
    content_hash: Vec<u8>,
}

impl FileKey {
    /// Builds the key from the content of a key file. `file_name` is only kept to be shown back - it is
    /// not read and does not have to be a path.
    pub fn from_bytes(file_name: &str, content: &[u8]) -> Result<FileKey> {
        debug!("File Key from bytes is called for key file {}", file_name);
        check_key_file_size(content.len() as u64)?;

        Ok(Self {
            file_name: file_name.into(),
            content_hash: Self::calculate_hash(content)?,
        })
    }

    /// Opens the file at the path and builds the key from its content
    pub fn open(key_file_name: &str) -> Result<FileKey> {
        debug!(
            "File Key open is called with key file name {}",
            key_file_name
        );
        if !key_file_name.trim().is_empty() & !Path::new(key_file_name).exists() {
            return Err(Error::NotFound(format!(
                "The key file {} is not valid one",
                key_file_name
            )));
        }
        // The size is checked before reading, so a file over the limit is never read into memory
        let file = File::open(key_file_name)?;
        check_key_file_size(file.metadata()?.len())?;

        let mut content = vec![];
        file.take(super::KEY_FILE_MAX_SIZE + 1)
            .read_to_end(&mut content)?;

        Self::from_bytes(key_file_name, &content)
    }

    // Need to return Result so that the invalid file name error can be propagated to caller
    pub(crate) fn from(key_file_name: Option<&str>) -> Result<Option<FileKey>> {
        let key_file: Result<Option<FileKey>> = match key_file_name {
            Some(n) if !n.trim().is_empty() => Ok(Some(FileKey::open(n)?)),
            Some(_) => Ok(None),
            None => Ok(None),
        };
        key_file
    }

    pub(crate) fn content_hash(&self) -> Vec<u8> {
        self.content_hash.clone()
    }

    /// The name the key was built with: a path on desktop, the name to show on mobile
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Whether both keys open the same thing. By content, not by name: two files with one name can be
    /// different keys, and one key can be picked again under another name
    pub(crate) fn same_key_as(&self, other: &FileKey) -> bool {
        self.content_hash == other.content_hash
    }

    // Never overwrites: an existing file may be the key of another database, and replacing it
    // locks that database for good. Fails with io::ErrorKind::AlreadyExists; asking the user
    // to confirm an overwrite is up to the UI
    pub fn create_xml_key_file(key_file_name: &str) -> Result<()> {
        let mut file_buf = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(key_file_name)?;

        Self::write_xml(&mut file_buf)
    }

    /// A new key file (32 random bytes, xml KeyFile 2.0) as bytes - for a client that writes files
    /// itself. The guard of `create_xml_key_file` does not come along: writing over an existing file
    /// is the caller's to refuse
    pub fn generate_xml_key_file() -> Result<Vec<u8>> {
        let mut content = vec![];
        Self::write_xml(&mut content)?;
        Ok(content)
    }

    pub fn write_xml<W: Write>(buf: &mut W) -> Result<()> {
        let mut xml_writer = FileKeyXmlWriter::new_with_indent(buf);
        let key_file_data = KeyFileData::generate_key_data()?;
        xml_writer.write(&key_file_data)
    }

    /// The 32 bytes of the key, read the way KeePass and KeePassXC read a key file (pass-docs, Step 113): an xml
    /// `<KeyFile>` - version 1.0 or 2.0; otherwise exactly 32 bytes are the key as they are, exactly 64 hex
    /// characters are the key hex encoded, and anything else is hashed whole.
    fn calculate_hash(buf: &[u8]) -> Result<Vec<u8>> {
        match Self::try_parse_xml(buf) {
            Ok(key_file_data) => {
                debug!("Found xml key file");
                key_file_data.key()
            }
            Err(Error::NotXmlKeyFile) => {
                debug!("Key file is not xml based one");
                Self::plain_key(buf)
            }
            Err(e) => Err(e),
        }
    }

    fn plain_key(buf: &[u8]) -> Result<Vec<u8>> {
        if buf.len() == RAW_KEY_LEN {
            return Ok(buf.to_vec());
        }
        if buf.len() == HEX_KEY_LEN {
            // 64 bytes that are not all hex digits are a file like any other
            if let Ok(key) = hex::decode(buf) {
                return Ok(key);
            }
        }
        crypto::sha256_hash_from_slice(buf)
    }

    fn try_parse_xml(buf: &[u8]) -> Result<KeyFileData> {
        let mut reader = FileKeyXmlReader::new(buf as &[u8]);
        let r = reader.parse()?;
        Ok(r)
    }
}

#[derive(Default)]
pub struct KeyFileData {
    pub version: Option<String>,
    pub hash: Option<String>,
    pub data: Option<String>,
}

// Written by hand: the derived one would print the secret - see crate::redacted
impl std::fmt::Debug for KeyFileData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyFileData")
            .field("version", &self.version)
            .field("hash", &crate::redacted::redacted_opt(&self.hash))
            .field("data", &crate::redacted::redacted_opt(&self.data))
            .finish()
    }
}

/// The versions of `<KeyFile>` there are: 1.0 - the key in base64, KeePass before 2.47; 2.0 - hex with a checksum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFileVersion {
    V1,
    V2,
}

impl KeyFileData {
    /// The version of the file - "1.0" and "2.0", as KeePass writes them ("1.00" too); none for anything else
    pub(crate) fn key_version(&self) -> Option<KeyFileVersion> {
        match self.version.as_deref().map(str::trim) {
            Some(v) if v.starts_with("1.0") => Some(KeyFileVersion::V1),
            Some(v) if v.starts_with("2.0") => Some(KeyFileVersion::V2),
            _ => None,
        }
    }

    /// The key of the file: base64 for 1.0, hex checked against its checksum for 2.0
    pub fn key(&self) -> Result<Vec<u8>> {
        match self.key_version() {
            Some(KeyFileVersion::V1) => match &self.data {
                Some(data) => util::base64_decode(data),
                None => Err(Error::DataError("Key file invalid key data")),
            },
            Some(KeyFileVersion::V2) => self.verify_checksum(),
            None => Err(Error::UnsupportedXmlKeyFileVersion),
        }
    }

    // Gets the key hash after verifying the checksum
    pub fn verify_checksum(&self) -> Result<Vec<u8>> {
        if let (Some(data), Some(hash)) = (&self.data, &self.hash) {
            // Move this joining logic to xml_reading side
            // let d = data
            //     .split_whitespace()
            //     .map(|s| s)
            //     .collect::<Vec<_>>()
            //     .join("");
            let data_vec = hex::decode(data)?;
            let d = crypto::sha256_hash_from_slice(&data_vec)?;
            let h = hex::decode(hash)?;
            // First 4 bytes of hash of the decoded key data should match the checksum hash bytes
            if d[..4] != h {
                return Err(Error::DataError("Key file checksum failed"));
            }
            debug!(
                "File key verify_checksum is called for xml based file key and found valid hash"
            );
            Ok(data_vec)
        } else {
            Err(Error::DataError("Key file invalid key data"))
        }
    }

    pub fn generate_key_data() -> Result<Self> {
        let data_vec = crypto::get_random_bytes::<32>()?;
        let data_vec_hash = crypto::sha256_hash_from_slice(&data_vec)?;
        let check_sum_hash = hex::encode_upper(&data_vec_hash[..4]);
        //let check_sum_hash =
        let data_hex = hex::encode_upper(&data_vec);

        Ok(Self {
            version: Some("2.0".into()),
            data: Some(data_hex),
            hash: Some(check_sum_hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FileKey, KeyFileData};
    use crate::{
        crypto, db::credential_limits::KEY_FILE_MAX_SIZE, error::Error, xml_parse::FileKeyXmlWriter,
    };

    fn temp_file(test: &str, content: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pass_core_test_{}_{}.key",
            test,
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();
        path
    }

    // --- Formats as KeePass / KeePassXC read them (Step 113) ---

    fn key_of(content: &[u8]) -> Vec<u8> {
        FileKey::from_bytes("key", content).unwrap().content_hash()
    }

    fn sha256(content: &[u8]) -> Vec<u8> {
        crypto::sha256_hash_from_slice(content).unwrap()
    }

    const KEY: [u8; 32] = [7u8; 32];

    fn xml_v2(decl: bool, version: &str, hash: &str, data: &str) -> Vec<u8> {
        format!(
            "{}<KeyFile>\n<Meta><Version>{}</Version></Meta>\n<Key><Data Hash=\"{}\">{}</Data></Key>\n</KeyFile>\n",
            if decl { "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" } else { "" },
            version,
            hash,
            data
        )
        .into_bytes()
    }

    fn checksum(key: &[u8]) -> String {
        hex::encode_upper(&sha256(key)[..4])
    }

    #[test]
    fn exactly_32_bytes_are_the_key_as_they_are() {
        assert_eq!(key_of(&KEY), KEY.to_vec());
    }

    #[test]
    fn a_byte_more_or_less_than_32_is_hashed() {
        assert_eq!(key_of(&[7u8; 31]), sha256(&[7u8; 31]));
        assert_eq!(key_of(&[7u8; 33]), sha256(&[7u8; 33]));
    }

    #[test]
    fn exactly_64_hex_characters_are_the_key_decoded_in_either_case() {
        assert_eq!(key_of(hex::encode(KEY).as_bytes()), KEY.to_vec());
        assert_eq!(key_of(hex::encode_upper(KEY).as_bytes()), KEY.to_vec());
    }

    #[test]
    fn sixty_four_bytes_that_are_not_hex_are_hashed() {
        let content = [b'z'; 64];
        assert_eq!(key_of(&content), sha256(&content));
    }

    #[test]
    fn hex_with_a_line_break_after_it_is_hashed_as_keepassxc_does() {
        let content = format!("{}\n", hex::encode(KEY)).into_bytes();
        assert_eq!(key_of(&content), sha256(&content));
    }

    #[test]
    fn an_xml_key_file_of_version_1_has_its_key_in_base64() {
        for version in ["1.0", "1.00"] {
            let content = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>{}</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data>{}</Data>\n\t</Key>\n</KeyFile>\n",
                version,
                crate::util::base64_encode(KEY)
            );
            assert_eq!(key_of(content.as_bytes()), KEY.to_vec(), "{version}");
        }
    }

    #[test]
    fn an_xml_key_file_without_the_declaration_is_read_as_xml() {
        let content = xml_v2(false, "2.0", &checksum(&KEY), &hex::encode_upper(KEY));
        assert_eq!(key_of(&content), KEY.to_vec());
    }

    #[test]
    fn xml_that_is_not_a_key_file_is_hashed_whole() {
        let content = b"<?xml version=\"1.0\"?>\n<Settings><Theme>dark</Theme></Settings>\n";
        assert_eq!(key_of(content), sha256(content));
    }

    #[test]
    fn a_key_file_broken_off_is_hashed_whole_as_keepassxc_does() {
        let mut content = xml_v2(true, "2.0", &checksum(&KEY), &hex::encode_upper(KEY));
        content.truncate(content.len() / 2);
        assert_eq!(key_of(&content), sha256(&content));
    }

    #[test]
    fn a_key_file_of_a_version_not_known_is_refused() {
        let content = xml_v2(true, "3.0", &checksum(&KEY), &hex::encode_upper(KEY));
        assert!(matches!(
            FileKey::from_bytes("key", &content),
            Err(Error::UnsupportedXmlKeyFileVersion)
        ));
    }

    #[test]
    fn a_key_file_without_a_version_is_refused() {
        let content = b"<KeyFile><Key><Data>AAAA</Data></Key></KeyFile>";
        assert!(matches!(
            FileKey::from_bytes("key", content),
            Err(Error::UnsupportedXmlKeyFileVersion)
        ));
        assert!(matches!(
            FileKey::from_bytes("key", b"<?xml version=\"1.0\"?><KeyFile/>"),
            Err(Error::UnsupportedXmlKeyFileVersion)
        ));
    }

    #[test]
    fn a_key_file_of_version_2_with_a_wrong_checksum_is_refused() {
        let content = xml_v2(true, "2.0", "FFFFFFFF", &hex::encode_upper(KEY));
        assert!(matches!(
            FileKey::from_bytes("key", &content),
            Err(Error::DataError(_))
        ));
    }

    // --- Key file as bytes (Step 29) ---

    #[test]
    fn bytes_give_the_same_key_as_the_file_for_an_xml_key_file() {
        let content = FileKey::generate_xml_key_file().unwrap();
        let path = temp_file("bytes_xml", &content);

        let from_file = FileKey::open(path.to_str().unwrap()).unwrap();
        let from_bytes = FileKey::from_bytes("any name", &content).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(from_file.content_hash(), from_bytes.content_hash());
    }

    #[test]
    fn bytes_give_the_same_key_as_the_file_for_any_other_file() {
        let content = b"not a key file at all, just some bytes";
        let path = temp_file("bytes_raw", content);

        let from_file = FileKey::open(path.to_str().unwrap()).unwrap();
        let from_bytes = FileKey::from_bytes("photo.jpg", content).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(from_file.content_hash(), from_bytes.content_hash());
    }

    #[test]
    fn the_name_is_kept_only_to_be_shown() {
        let key = FileKey::from_bytes("my.keyx", b"content").unwrap();
        assert_eq!(key.file_name(), "my.keyx");
    }

    #[test]
    fn a_generated_key_file_is_a_valid_xml_key_of_32_bytes() {
        let content = FileKey::generate_xml_key_file().unwrap();
        // Parsed as xml with a correct checksum, not hashed as a plain file
        let key = FileKey::from_bytes("new.keyx", &content).unwrap();
        assert_eq!(key.content_hash().len(), 32);
        assert_eq!(
            key.content_hash(),
            FileKey::try_parse_xml(&content)
                .unwrap()
                .verify_checksum()
                .unwrap()
        );
    }

    #[test]
    fn two_generated_key_files_are_different_keys() {
        let first = FileKey::from_bytes("a", &FileKey::generate_xml_key_file().unwrap()).unwrap();
        let second = FileKey::from_bytes("a", &FileKey::generate_xml_key_file().unwrap()).unwrap();
        assert!(!first.same_key_as(&second));
    }

    #[test]
    fn the_same_content_under_another_name_is_the_same_key() {
        let first = FileKey::from_bytes("old-name.keyx", b"content").unwrap();
        let second = FileKey::from_bytes("new-name.keyx", b"content").unwrap();
        assert!(first.same_key_as(&second));
    }

    #[test]
    fn bytes_over_the_limit_are_refused() {
        let content = vec![0u8; KEY_FILE_MAX_SIZE as usize + 1];
        assert!(matches!(
            FileKey::from_bytes("video.mp4", &content),
            Err(Error::KeyFileTooLarge)
        ));
    }

    #[test]
    fn bytes_of_the_limit_are_accepted() {
        let content = vec![0u8; KEY_FILE_MAX_SIZE as usize];
        assert!(FileKey::from_bytes("photo.jpg", &content).is_ok());
    }

    #[test]
    fn a_file_over_the_limit_is_refused() {
        let path = temp_file("over_limit", b"");
        // Sparse on most file systems: the size is what is checked, before any reading
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(KEY_FILE_MAX_SIZE + 1)
            .unwrap();

        let result = FileKey::open(path.to_str().unwrap());
        std::fs::remove_file(&path).unwrap();

        assert!(matches!(result, Err(Error::KeyFileTooLarge)));
    }

    // --- Non-ignored unit tests ---

    #[test]
    fn key_file_data_generate_produces_valid_data() {
        let kfd = KeyFileData::generate_key_data().unwrap();
        assert_eq!(kfd.version.as_deref(), Some("2.0"));
        assert!(kfd.data.is_some());
        assert!(kfd.hash.is_some());
    }

    #[test]
    fn key_file_data_generate_and_verify_roundtrip() {
        let kfd = KeyFileData::generate_key_data().unwrap();
        let result = kfd.verify_checksum();
        assert!(result.is_ok());
        // Decoded data should be 32 bytes (256-bit key)
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn key_file_data_verify_tampered_hash_fails() {
        let mut kfd = KeyFileData::generate_key_data().unwrap();
        kfd.hash = Some("FFFFFFFF".into());
        assert!(kfd.verify_checksum().is_err());
    }

    #[test]
    fn key_file_data_verify_missing_data_fails() {
        let kfd = KeyFileData {
            version: Some("2.0".into()),
            hash: Some("AABBCCDD".into()),
            data: None,
        };
        assert!(kfd.verify_checksum().is_err());
    }

    #[test]
    fn key_file_data_verify_missing_hash_fails() {
        let kfd = KeyFileData {
            version: Some("2.0".into()),
            hash: None,
            data: Some("AABBCCDD".into()),
        };
        assert!(kfd.verify_checksum().is_err());
    }

    #[test]
    fn file_key_write_xml_produces_non_empty_output() {
        let mut buf = Vec::new();
        FileKey::write_xml(&mut buf).unwrap();
        assert!(!buf.is_empty());
        let xml = String::from_utf8(buf).unwrap();
        assert!(xml.contains("KeyFile"));
        assert!(xml.contains("Data"));
    }

    #[test]
    fn file_key_from_none_returns_none() {
        let result = FileKey::from(None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn file_key_from_empty_string_returns_none() {
        let result = FileKey::from(Some("")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn file_key_from_whitespace_returns_none() {
        let result = FileKey::from(Some("   ")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn verify_xml_key_file() {
        // Generate a valid xml key file's content in memory (same helper the
        // production `write_xml` uses) so we know the expected raw key data
        // up front, then write it to a temp file and open it via `FileKey::open`.
        let key_file_data = KeyFileData::generate_key_data().unwrap();
        let expected_data = hex::decode(key_file_data.data.as_ref().unwrap()).unwrap();

        let mut buf: Vec<u8> = Vec::new();
        {
            let mut xml_writer = FileKeyXmlWriter::new_with_indent(&mut buf);
            xml_writer.write(&key_file_data).unwrap();
        }

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "pass_core_test_verify_xml_key_file_{}.keyx",
            std::process::id()
        ));
        std::fs::write(&path, &buf).unwrap();

        let fk = FileKey::open(path.to_str().unwrap()).unwrap();
        let h = fk.content_hash();

        std::fs::remove_file(&path).unwrap();

        assert_eq!(expected_data, h);
    }

    #[test]
    fn verify_any_key_file() {
        // A "raw" (non-xml) key file: its content hash is just sha256 of the bytes.
        let content = b"some arbitrary key file bytes used only in this test";

        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "pass_core_test_verify_any_key_file_{}.bin",
            std::process::id()
        ));
        std::fs::write(&path, content).unwrap();

        let fk = FileKey::open(path.to_str().unwrap()).unwrap();
        let h = fk.content_hash();

        std::fs::remove_file(&path).unwrap();

        let expected = crypto::sha256_hash_from_slice(content).unwrap();
        assert_eq!(expected, h);
    }
}
