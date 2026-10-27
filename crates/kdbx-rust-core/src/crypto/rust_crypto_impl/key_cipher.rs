use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::crypto;
use crate::error::{Error, Result};

// AES-256-GCM protection of the database keys kept in memory / in the platform key store
pub struct KeyCipher {
    // key is 256 bits - 32 bytes
    pub(crate) key: Vec<u8>,
    // nonce is 96 bits - 12 bytes
    pub(crate) nonce: Vec<u8>,
}

impl KeyCipher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            key: crypto::get_random_bytes::<32>()?,
            nonce: crypto::get_random_bytes::<12>()?,
        })
    }

    pub fn from(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (cipher, nonce) = self.cipher_and_nonce()?;
        cipher.encrypt(&nonce, data).map_err(|_| Error::Encryption)
    }

    // Fails on a wrong key/nonce or on a tampered ciphertext (tag verification)
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let (cipher, nonce) = self.cipher_and_nonce()?;
        cipher.decrypt(&nonce, data).map_err(|_| Error::Decryption)
    }

    fn cipher_and_nonce(&self) -> Result<(Aes256Gcm, Nonce<Aes256Gcm>)> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| Error::InvalidCryptoInputLength("AES-256-GCM key"))?;
        let nonce = Nonce::<Aes256Gcm>::try_from(self.nonce.as_slice())
            .map_err(|_| Error::InvalidCryptoInputLength("AES-256-GCM nonce"))?;
        Ok((cipher, nonce))
    }
}
