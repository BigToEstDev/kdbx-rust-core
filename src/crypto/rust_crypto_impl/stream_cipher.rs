use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

use crate::constants::inner_header_type::CHACHA20_STREAM;
use crate::error::{Error, Result};

// Inner stream cipher of KDBX4 protecting `Protected="True"` values in the XML.
// One keystream runs through the whole document in order, so values must be processed
// in document order and every value must consume the keystream exactly once.
pub struct ProtectedContentStreamCipher {
    cipher: ChaCha20,
}

// ChaCha20 keeps key material in its state: do not print it
impl std::fmt::Debug for ProtectedContentStreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectedContentStreamCipher")
            .finish_non_exhaustive()
    }
}

impl ProtectedContentStreamCipher {
    pub fn try_from(cipher_id: u32, inner_stream_key: &Vec<u8>) -> Result<Self> {
        if cipher_id != CHACHA20_STREAM {
            return Err(Error::UnsupportedStreamCipher(
                "Only CHACHA20 cipher scheme is supported for encrypting/decrypting for in memory protection of Projected string and binary values".into(),
            ));
        }
        // KDBX4 spec: SHA-512(inner stream key) -> first 32 bytes key, next 12 bytes nonce
        let h = crate::crypto::sha512_hash_from_slice_vecs(&[inner_stream_key])?;
        let cipher = ChaCha20::new_from_slices(&h[..32], &h[32..44])
            .map_err(|_| Error::InvalidCryptoInputLength("ChaCha20 inner stream key or IV"))?;
        Ok(ProtectedContentStreamCipher { cipher })
    }

    pub fn process(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut buf = data.to_vec();
        self.cipher
            .try_apply_keystream(&mut buf)
            .map_err(|_| Error::Encryption)?;
        Ok(buf)
    }

    // Decodes and decrypts a protected value. The keystream is advanced before the UTF-8 check,
    // so a failed value does not desynchronize the following ones.
    pub fn process_basic64_str(&mut self, b64_str: &str) -> Result<String> {
        if b64_str.is_empty() {
            return Ok(String::new());
        }
        let decoded = STANDARD.decode(b64_str)?;
        let decrypted = self.process(&decoded)?;
        // Invalid UTF-8 means a wrong inner stream key or corrupted data - reported as an error
        // instead of building a String that breaks its UTF-8 invariant
        Ok(String::from_utf8(decrypted)?)
    }

    // The content string data is encrypted and the base 64 of the encrypted bytes data is returned
    pub fn process_content_b64_str(&mut self, content: &str) -> Result<String> {
        if content.is_empty() {
            return Err(Error::DataError(
                "Protected data content cannot be an empty string",
            ));
        }
        let encrypted = self.process(content.as_bytes())?;
        Ok(STANDARD.encode(encrypted))
    }
}
