use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

use crate::{
    constants,
    error::{Error, Result},
};

// Length of the transformed key and of the generated salt (KeePass uses 32 bytes for both)
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 32;

// KDBX stores Argon2 memory in bytes, the Argon2 API takes 1 KiB blocks
const BYTES_PER_KIB: u64 = 1024;

// Argon2 versions allowed by the KDBX4 spec: 0x10 and 0x13
const ARGON2_VERSION_10: u32 = 0x10;
const ARGON2_VERSION_13: u32 = 0x13;

// Argon2 variant of a KDBX4 file. It is defined only by `KdfAlgorithm` (`Argon2d`/`Argon2id`),
// never by a field of `Argon2Kdf`: a separate field could disagree with the enum, which made a
// database created as Argon2id silently use Argon2d.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Argon2Variant {
    D,
    Id,
}

impl Argon2Variant {
    // The uuids used by KeePass KDBX 4
    pub(crate) fn uuid_bytes(self) -> &'static [u8] {
        match self {
            Argon2Variant::D => constants::uuid::ARGON2_D_KDF,
            Argon2Variant::Id => constants::uuid::ARGON2_ID_KDF,
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Argon2Variant::D => Algorithm::Argon2d,
            Argon2Variant::Id => Algorithm::Argon2id,
        }
    }
}

// Parameters are shared by both variants. The salt is never serialized for the UI: it is read
// from the file header on load and regenerated on every save (see `reset_salt`).
#[derive(Clone, Deserialize, Serialize, Debug)]
// While deserializing, any missing fields are formed from the struct's implementation of Default
#[serde(default)]
pub struct Argon2Kdf {
    #[serde(skip)]
    pub(crate) salt: Vec<u8>,

    // In bytes, as stored in KDBX
    pub(crate) memory: u64,
    pub(crate) iterations: u64,
    pub(crate) parallelism: u32,
    pub(crate) version: u32,
}

impl Default for Argon2Kdf {
    fn default() -> Self {
        Self {
            salt: Vec::new(),
            memory: 64 * 1024 * 1024,
            iterations: 10,
            parallelism: 2,
            version: ARGON2_VERSION_13,
        }
    }
}

impl Argon2Kdf {
    // Creates argon2kdf with specific parameters values
    // The arg 'memory' size is in bytes
    pub(crate) fn from(memory: u64, iterations: u64, parallelism: u32) -> Self {
        Self {
            memory,
            iterations,
            parallelism,
            ..Self::default()
        }
    }

    // Called before every save, together with the master seed and encryption IV reset, so that
    // each saved file gets a fresh KDF salt (as KeePass does)
    pub(crate) fn reset_salt(&mut self) -> Result<()> {
        self.salt = super::get_random_bytes::<SALT_LEN>()?;
        Ok(())
    }

    pub(crate) fn transform_key(
        &self,
        variant: Argon2Variant,
        composite_key: &[u8],
    ) -> Result<Vec<u8>> {
        // Parameters may come from a foreign file: convert without truncating casts
        let m_cost = u32::try_from(self.memory / BYTES_PER_KIB).map_err(|_| {
            Error::Argon2Error(format!("memory {} bytes is too large", self.memory))
        })?;
        let t_cost = u32::try_from(self.iterations).map_err(|_| {
            Error::Argon2Error(format!("iterations {} is too large", self.iterations))
        })?;
        let version = match self.version {
            ARGON2_VERSION_10 => Version::V0x10,
            ARGON2_VERSION_13 => Version::V0x13,
            v => {
                return Err(Error::Argon2Error(format!(
                    "unsupported Argon2 version {:#x}",
                    v
                )))
            }
        };

        let params = Params::new(m_cost, t_cost, self.parallelism, Some(KEY_LEN))
            .map_err(|e| Error::Argon2Error(e.to_string()))?;

        // With the `parallel` feature lanes are computed on rayon threads
        let mut key = vec![0u8; KEY_LEN];
        Argon2::new(variant.algorithm(), version, params)
            .hash_password_into(composite_key, &self.salt, &mut key)
            .map_err(|e| Error::Argon2Error(e.to_string()))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::{Argon2Kdf, Argon2Variant, SALT_LEN};

    // Эталонные значения получены официальными биндингами референсной реализации Argon2
    // (argon2-cffi 25.1.0, крейт tools/kdbx-oracle), а не нашим кодом.
    //
    // Официальный вектор RFC 9106 через наш API недостижим: там salt 16 байт плюс secret и
    // associated data, а KDBX-путь не передаёт secret/ad. Поэтому вектор снят для нашей формы
    // параметров. Сам примитив против RFC 9106 проверяется тестами крейта `argon2`.

    const PASSWORD: [u8; 32] = [0x01; 32];
    const SALT: [u8; 32] = [0x02; 32];

    const MEMORY_8_MIB: u64 = 8 * 1024 * 1024;
    const ITERATIONS: u64 = 2;
    const PARALLELISM: u32 = 2;

    const EXPECTED_ARGON2D: &str =
        "c9bd6947c5082c4e2e634ea4d7863939e94b18b516505c372922f95df0ea5bb9";
    const EXPECTED_ARGON2ID: &str =
        "50b87226bb37ae4fb8d2ec86c5a944c4e361c7054f47a263df3a41911e56cba2";

    fn kdf_with_fixed_salt() -> Argon2Kdf {
        Argon2Kdf {
            salt: SALT.to_vec(),
            ..Argon2Kdf::from(MEMORY_8_MIB, ITERATIONS, PARALLELISM)
        }
    }

    fn transform(kdf: &Argon2Kdf, variant: Argon2Variant) -> crate::error::Result<Vec<u8>> {
        kdf.transform_key(variant, &PASSWORD)
    }

    #[test]
    fn verify_argon2d_reference_vector() {
        let transformed = transform(&kdf_with_fixed_salt(), Argon2Variant::D).unwrap();
        assert_eq!(hex::encode(&transformed), EXPECTED_ARGON2D);
    }

    #[test]
    fn verify_argon2id_reference_vector() {
        let transformed = transform(&kdf_with_fixed_salt(), Argon2Variant::Id).unwrap();
        assert_eq!(hex::encode(&transformed), EXPECTED_ARGON2ID);
    }

    // Варианты должны давать разный результат: если вариант где-то потеряется,
    // оба теста выше могут остаться зелёными по совпадению только при одинаковых выходах.
    #[test]
    fn verify_argon2_variants_differ() {
        let kdf = kdf_with_fixed_salt();
        let d = transform(&kdf, Argon2Variant::D).unwrap();
        let id = transform(&kdf, Argon2Variant::Id).unwrap();
        assert_ne!(d, id, "Argon2d и Argon2id дали одинаковый результат");
    }

    // uuid_bytes должен соответствовать варианту — иначе KDBX-файл будет помечен не тем KDF
    #[test]
    fn verify_variant_uuids() {
        use crate::constants::uuid::{ARGON2_D_KDF, ARGON2_ID_KDF};
        assert_eq!(Argon2Variant::D.uuid_bytes(), ARGON2_D_KDF);
        assert_eq!(Argon2Variant::Id.uuid_bytes(), ARGON2_ID_KDF);
    }

    // Версия 0x10 разрешена спецификацией KDBX4 и даёт другой ключ, чем 0x13 —
    // раньше C-код игнорировал поле и всегда считал 0x13
    #[test]
    fn verify_version_is_used() {
        let v13 = transform(&kdf_with_fixed_salt(), Argon2Variant::D).unwrap();
        let v10 = transform(
            &Argon2Kdf {
                version: 0x10,
                ..kdf_with_fixed_salt()
            },
            Argon2Variant::D,
        )
        .unwrap();
        assert_ne!(v10, v13);
    }

    #[test]
    fn verify_unsupported_version_rejected() {
        let kdf = Argon2Kdf {
            version: 0x12,
            ..kdf_with_fixed_salt()
        };
        assert!(transform(&kdf, Argon2Variant::D).is_err());
    }

    #[test]
    fn verify_too_large_parameters_rejected() {
        let kdf = Argon2Kdf {
            iterations: u64::from(u32::MAX) + 1,
            ..kdf_with_fixed_salt()
        };
        assert!(transform(&kdf, Argon2Variant::D).is_err());

        let kdf = Argon2Kdf {
            memory: (u64::from(u32::MAX) + 1) * 1024,
            ..kdf_with_fixed_salt()
        };
        assert!(transform(&kdf, Argon2Variant::D).is_err());
    }

    // Соль больше не генерируется в Default: без reset_salt ключ вывести нельзя,
    // а не молча с пустой/нулевой солью
    #[test]
    fn verify_empty_salt_rejected() {
        let kdf = Argon2Kdf::from(MEMORY_8_MIB, ITERATIONS, PARALLELISM);
        assert!(transform(&kdf, Argon2Variant::D).is_err());
    }

    #[test]
    fn verify_reset_salt_generates_new_salt() {
        let mut kdf = kdf_with_fixed_salt();
        kdf.reset_salt().unwrap();
        assert_eq!(kdf.salt.len(), SALT_LEN);
        assert_ne!(kdf.salt, SALT.to_vec());

        let previous = kdf.salt.clone();
        kdf.reset_salt().unwrap();
        assert_ne!(kdf.salt, previous);
    }

    // Клиент может прислать устаревшее поле variant — оно игнорируется, а соль в JSON
    // не попадает ни при сериализации, ни при десериализации
    #[test]
    fn verify_serde_has_no_variant_and_salt() {
        let json = serde_json::to_value(kdf_with_fixed_salt()).unwrap();
        assert!(json.get("variant").is_none());
        assert!(json.get("salt").is_none());

        let kdf: Argon2Kdf =
            serde_json::from_value(serde_json::json!({ "variant": 2, "salt": [1, 2, 3] })).unwrap();
        assert!(kdf.salt.is_empty());
    }
}
