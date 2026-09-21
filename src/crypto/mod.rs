pub mod kdf;
use crate::{
    constants,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};

mod rust_crypto_impl;
pub use rust_crypto_impl::*;

// Provides the encryption and decryption
#[derive(Debug)]
pub enum ContentCipher {
    ChaCha20([u8; 12]),
    Aes256([u8; 16]),
}

// Moved from db module
// TODO: Combine ContentCipher and ContentCipherId ?
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ContentCipherId {
    ChaCha20,
    Aes256,
    UnKnownCipher,
}

impl ContentCipherId {
    // Gets the UUID and Encryption IV of the supported algorithm
    pub fn uuid_with_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rn16, rn12) = get_random_bytes_2::<16, 12>()?;
        match self {
            ContentCipherId::Aes256 => Ok((constants::uuid::AES256.to_vec(), rn16)),
            ContentCipherId::ChaCha20 => Ok((constants::uuid::CHACHA20.to_vec(), rn12)),
            _ => Err(Error::UnsupportedCipher(vec![])),
        }
    }

    // Generates the random master seed and iv for the selected algorithm
    pub fn generate_master_seed_iv(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let (rn32, rn16, rn12) = get_random_bytes_3::<32, 16, 12>()?;
        match self {
            ContentCipherId::Aes256 => Ok((rn32, rn16)),
            ContentCipherId::ChaCha20 => Ok((rn32, rn12)),
            _ => Err(Error::UnsupportedCipher(vec![])),
        }
    }
}

#[test]
pub fn init_log_lib_info() {
    crate::util::init_test_logging();
    print_crypto_lib_info();
}

#[cfg(test)]
#[allow(unused)]
mod tests {
    use super::*;
    use crate::util::init_test_logging;
    #[test]
    fn veriy_aes_gcm() {
        let kc = KeyCipher::new().unwrap();

        assert_eq!(kc.key.len(), 32);
        assert_eq!(kc.nonce.len(), 12);

        let plain_text = b"Hello world";
        let enc_result = kc.encrypt(plain_text).unwrap();
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(), &dec_result);

        // key and nonce moved from kc simulating stored somewhere
        let key = kc.key;
        let nonce = kc.nonce;
        // Recreate a new cipher from the previous key and nonce
        let kc = KeyCipher::from(&key, &nonce);
        let dec_result = kc.decrypt(&enc_result).unwrap();
        assert_eq!(plain_text.as_ref(), &dec_result);
    }
    #[test]
    fn verify_aes256_encrypt_decrypt() {
        init_test_logging();
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        let text = "Hello World!";
        let key = get_random_bytes::<32>().unwrap();

        let encrypted = cipher.encrypt(text.as_bytes(), &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(text.as_bytes(), decrypted);
    }

    // Generates deterministic pseudo-random data in memory instead of reading an
    // external file (no local fixtures in this repo).
    fn generated_data(size: usize) -> Vec<u8> {
        let mut data = Vec::with_capacity(size);
        let mut state: u32 = 0x1234_5678;
        for _ in 0..size {
            // Simple xorshift32 PRNG - deterministic, no external deps needed
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            data.push((state & 0xFF) as u8);
        }
        data
    }

    #[test]
    fn verify_aes256_file_data_encrypt_decrypt() {
        init_log_lib_info();
        let (uuid, enc_iv) = ContentCipherId::Aes256.uuid_with_iv().unwrap();
        let cipher = ContentCipher::try_from(&uuid, &enc_iv).unwrap();

        // A few MB of generated data, large enough to exercise multi-block encryption
        let data: Vec<u8> = generated_data(4 * 1024 * 1024);
        let key = get_random_bytes::<32>().unwrap();

        let encrypted = cipher.encrypt(&data, &key).unwrap();
        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();

        assert_eq!(data, decrypted);
    }

    // Need to add to Cargo.toml to test this
    // alkali = { version = "0.3.0", features = ["aes","hazmat"] }
    /*
    #[test]
    fn verify_hash256_4() {
        use std::time::{Duration, Instant};
        use std::{fs, io};
        // hex d4e06bcc6f614cd4b261fc6034529edb205b31b0e56824490a91350c3640806a
        let path = "/Users/jeyasankar/Downloads/Android/android-studio-2021.2.1.16-mac_arm.dmg";
        let input = fs::File::open(path).unwrap();
        let mut reader = BufReader::new(input);

        let start = Instant::now();

        let digest = {
            let mut hasher = alkali::hash::sha2::sha256::Multipart::new().unwrap();
            println!("Started hashing ...");

            // Reads the complete file in one go
            // let mut buf = vec![];
            // reader.read_to_end(&mut buf).unwrap();
            // hasher.update(&buf).unwrap();
            // hasher.finish().unwrap()

            let mut buffer = [0; 1024];
            loop {
                let count = reader.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            hasher.calculate()
        };

        let duration = start.elapsed();
        println!("Completed hashing ...duration {:?}", duration);

        println!("Digest hex is {}", hex::encode(&digest.0));

        // use alkali::hash::sha2;
        // let message = b"Here's some message we wish to hash :)";
        // let hash = sha2::hash(message).unwrap();
        // assert_eq!(
        //     hash,
        //     sha2::Digest([
        //         0xb7, 0xee, 0x33, 0x80, 0x83, 0xf0, 0x41, 0x65, 0xc1, 0xff, 0xfb, 0xb2, 0x14, 0x6f,
        //         0x18, 0x8b, 0x9c, 0x01, 0x31, 0xd3, 0x0e, 0x7c, 0x45, 0x36, 0xbe, 0xb3, 0x4a, 0x1d,
        //         0xb0, 0x2d, 0x86, 0x9d, 0x87, 0x1a, 0x1c, 0x84, 0xd7, 0x9b, 0x9d, 0xe3, 0x15, 0xc3,
        //         0xb4, 0x2d, 0x9a, 0xb9, 0x54, 0x25, 0x7a, 0xf9, 0x06, 0x28, 0x66, 0x8d, 0x9a, 0xa5,
        //         0x31, 0x45, 0x19, 0xbc, 0x4c, 0x2f, 0xcb, 0xa4
        //     ])
        // );
    }
    */

    // ---------------------------------------------------------------------
    // Векторы из спецификаций. В отличие от round-trip тестов выше, они ловят
    // симметричные ошибки: реализация, которая шифрует и расшифровывает
    // "неправильно, но согласованно", такие проверки не пройдёт.
    //
    // Все значения сверены с независимыми реализациями (hashlib, pycryptodomex,
    // см. tools/kdbx-oracle) и совпали с текстом спецификаций.
    // ---------------------------------------------------------------------

    // RFC 4231, Test Case 2 (и RFC 2202 Test Case 2 для SHA-1)
    const HMAC_KEY: &[u8] = b"Jefe";
    const HMAC_DATA: &[u8] = b"what do ya want for nothing?";

    #[test]
    fn verify_hmac_sha1_rfc4231_tc2() {
        let mac = super::hmac_sha1_from_slice(HMAC_KEY, HMAC_DATA).unwrap();
        assert_eq!(
            hex::encode(&mac),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn verify_hmac_sha256_rfc4231_tc2() {
        let mac = super::hmac_sha256_from_slice(HMAC_KEY, HMAC_DATA).unwrap();
        assert_eq!(
            hex::encode(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn verify_hmac_sha512_rfc4231_tc2() {
        let mac = super::hmac_sha512_from_slice(HMAC_KEY, HMAC_DATA).unwrap();
        assert_eq!(
            hex::encode(&mac),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                .replace(char::is_whitespace, "")
        );
    }

    // verify_hmac_sha256 используется при чтении KDBX (проверка HMAC блоков),
    // поэтому проверяем и его — на том же векторе.
    #[test]
    fn verify_hmac_sha256_verification_helper() {
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert!(super::verify_hmac_sha256(HMAC_KEY, &[HMAC_DATA], &expected).unwrap());

        let mut wrong = expected.clone();
        wrong[0] ^= 0x01;
        assert!(!super::verify_hmac_sha256(HMAC_KEY, &[HMAC_DATA], &wrong).unwrap());
    }

    // NIST FIPS 180-4, приложение с примерами: хэш строки "abc"
    #[test]
    fn verify_sha256_nist_abc() {
        let hash = super::sha256_hash_from_slice(b"abc").unwrap();
        assert_eq!(
            hex::encode(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn verify_sha512_nist_abc() {
        let data = b"abc".to_vec();
        let hash = super::sha512_hash_from_slice_vecs(&[&data]).unwrap();
        assert_eq!(
            hex::encode(&hash),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(char::is_whitespace, "")
        );
    }

    // NIST SP 800-38A, F.2.5 (CBC-AES256.Encrypt).
    //
    // Наш encrypt_aes256 добавляет PKCS7-паддинг, а в векторе NIST длина открытого текста
    // кратна блоку — поэтому шифртекст NIST должен быть ПРЕФИКСОМ нашего результата, а
    // последний блок паддинга проверяем отдельным сравнением.
    const AES_KEY_HEX: &str =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const AES_IV_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const AES_PLAIN_HEX: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    const AES_CIPHER_HEX: &str = "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b";

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.replace(char::is_whitespace, "")).unwrap()
    }

    #[test]
    fn verify_aes256_cbc_nist_sp800_38a_vector() {
        let key = unhex(AES_KEY_HEX);
        let iv = unhex(AES_IV_HEX);
        let plain = unhex(AES_PLAIN_HEX);
        let expected = unhex(AES_CIPHER_HEX);

        // block_cipher наружу не реэкспортируется, поэтому идём публичным путём —
        // тем же, которым пользуется чтение/запись KDBX
        let cipher = super::ContentCipher::try_from(crate::constants::uuid::AES256, &iv).unwrap();
        let encrypted = cipher.encrypt(&plain, &key).unwrap();

        // 4 блока вектора + 1 блок PKCS7
        assert_eq!(encrypted.len(), expected.len() + 16);
        assert_eq!(
            &encrypted[..expected.len()],
            &expected[..],
            "шифртекст не совпал с вектором NIST SP 800-38A F.2.5"
        );

        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plain);
    }

    // RFC 8439, A.2 Test Vector #1: нулевой ключ, нулевой nonce, counter = 0.
    // Шифрование 64 нулевых байт даёт ровно первый блок keystream.
    #[test]
    fn verify_chacha20_rfc8439_a2_vector() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plain = vec![0u8; 64];

        let cipher =
            super::ContentCipher::try_from(crate::constants::uuid::CHACHA20, &nonce).unwrap();
        let encrypted = cipher.encrypt(&plain, &key).unwrap();
        assert_eq!(
            hex::encode(&encrypted),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
                .replace(char::is_whitespace, ""),
            "keystream не совпал с вектором RFC 8439 A.2 #1"
        );

        let decrypted = cipher.decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plain);
    }
}
