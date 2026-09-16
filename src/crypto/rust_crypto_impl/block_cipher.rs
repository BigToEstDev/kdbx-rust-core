use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use log::debug;

use crate::constants::uuid::{AES256, CHACHA20};
use crate::crypto::ContentCipher;
use crate::error::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

// Outer (database content) ciphers of KDBX4: AES-256-CBC with PKCS7 padding and
// ChaCha20 (IETF, RFC 8439: 96-bit nonce, counter starts at 0)
impl ContentCipher {
    // enc_iv comes from the file header, so a wrong length means a corrupted or crafted file
    pub fn try_from(cipher_id: &[u8], enc_iv: &[u8]) -> Result<Self> {
        match cipher_id {
            CHACHA20 => enc_iv
                .try_into()
                .map(ContentCipher::ChaCha20)
                .map_err(|_| Error::InvalidCryptoInputLength("ChaCha20 encryption IV")),
            AES256 => enc_iv
                .try_into()
                .map(ContentCipher::Aes256)
                .map_err(|_| Error::InvalidCryptoInputLength("AES-256 encryption IV")),
            _ => Err(Error::UnsupportedCipher(cipher_id.to_vec())),
        }
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            ContentCipher::ChaCha20(iv) => {
                debug!("decrypting ChaCha20");
                chacha20_apply(encrypted, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("decrypting Aes256");
                decrypt_aes256(encrypted, key, iv)
            }
        }
    }

    pub fn encrypt(&self, plain_data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            ContentCipher::ChaCha20(iv) => {
                debug!("encrypting ChaCha20");
                chacha20_apply(plain_data, key, iv)
            }
            ContentCipher::Aes256(iv) => {
                debug!("encrypting Aes256");
                encrypt_aes256(plain_data, key, iv)
            }
        }
    }
}

fn encrypt_aes256(plain_data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcEnc::new_from_slices(key, enc_iv)
        .map_err(|_| Error::InvalidCryptoInputLength("AES-256-CBC key or IV"))?;
    Ok(cipher.encrypt_padded_vec::<Pkcs7>(plain_data))
}

// A padding error here means a wrong key (or corrupted data): the HMAC block check normally
// rejects both before decryption is reached
fn decrypt_aes256(encrypted: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256CbcDec::new_from_slices(key, enc_iv)
        .map_err(|_| Error::InvalidCryptoInputLength("AES-256-CBC key or IV"))?;
    cipher
        .decrypt_padded_vec::<Pkcs7>(encrypted)
        .map_err(|_| Error::Decryption)
}

// Stream cipher: encryption and decryption are the same keystream XOR
fn chacha20_apply(data: &[u8], key: &[u8], enc_iv: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20::new_from_slices(key, enc_iv)
        .map_err(|_| Error::InvalidCryptoInputLength("ChaCha20 key or IV"))?;
    let mut buf = data.to_vec();
    cipher
        .try_apply_keystream(&mut buf)
        .map_err(|_| Error::Encryption)?;
    Ok(buf)
}
