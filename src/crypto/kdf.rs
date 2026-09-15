extern crate argon2_sys;
use argon2_sys::{
    argon2_ctx, argon2_error_message, argon2_type, Argon2_Context, ARGON2_OK, ARGON2_VERSION_13,
};
use std::ffi::CStr;

use crate::{
    constants,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};

pub trait Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>>;
}

// Argon2 variants are identified by these constants
// https://docs.rs/argon2-sys/0.1.0/argon2_sys/constant.Argon2_d.html
const VARIANT_ARGON2_D: u32 = 0;
const VARIANT_ARGON2_ID: u32 = 2;

// This variant is not used in KeePass
// const VARIANT_ARGON2_I: u32 = 1;

#[derive(Clone, Deserialize, Serialize, Debug)]
// While deserializing, any missing fields are formed from the struct's implementation of Default
#[serde(default)]
pub struct Argon2Kdf {
    #[serde(skip_serializing)]
    pub(crate) salt: Vec<u8>,

    pub(crate) memory: u64,
    pub(crate) iterations: u64,
    pub(crate) parallelism: u32,
    pub(crate) version: u32,

    variant: u32,
}

impl Default for Argon2Kdf {
    fn default() -> Self {
        // super module is crypto
        Self {
            memory: 67_108_864, // = 64 MB,
            // TODO(Step 10 p.5): salt generation moves out of Default/from into a fallible path
            salt: super::get_random_bytes::<32>().expect("OS CSPRNG unavailable"),
            iterations: 10,
            parallelism: 2,
            // hard code use of the default for now
            version: 19,
            variant: VARIANT_ARGON2_D,
        }
    }
}

impl Argon2Kdf {
    pub(crate) fn variant_2d() -> Self {
        Self::default()
    }

    pub(crate) fn variant_2id() -> Self {
        let mut argon_kdf = Self::default();
        argon_kdf.variant = VARIANT_ARGON2_ID;
        argon_kdf
    }

    // The uuids used by KeePass KDBX 4
    pub(crate) fn uuid_bytes(&self) -> &[u8] {
        if self.variant == VARIANT_ARGON2_D {
            constants::uuid::ARGON2_D_KDF
        } else {
            constants::uuid::ARGON2_ID_KDF
        }
    }

    // Creates argon2kdf with specific parameters values
    // The arg 'memory' size is in bytes
    pub(crate) fn from(memory: u64, iterations: u64, parallelism: u32) -> Self {
        Self {
            memory,
            // TODO(Step 10 p.5): salt generation moves out of Default/from into a fallible path
            salt: super::get_random_bytes::<32>().expect("OS CSPRNG unavailable"),
            iterations,
            parallelism,
            // hard code use of the default for now
            version: 19,
            variant: VARIANT_ARGON2_D,
        }
    }
}

impl Kdf for Argon2Kdf {
    fn transform_key(&self, composite_key: Vec<u8>) -> Result<Vec<u8>> {
        let (pwd, pwdlen) = (composite_key.as_ptr() as *mut u8, 32);
        let (salt, saltlen) = (self.salt.as_ptr() as *mut u8, 32);

        let mut buffer = vec![0u8; 32]; //output
        let (ad, adlen) = (::std::ptr::null_mut(), 0);
        let (secret, secretlen) = (::std::ptr::null_mut(), 0);

        let memory_cost = self.memory / 1024; //in Kb

        let mut context = Argon2_Context {
            out: buffer.as_mut_ptr(),
            outlen: buffer.len() as u32,
            pwd,
            pwdlen,
            salt,
            saltlen,
            secret,
            secretlen,
            ad,
            adlen,
            t_cost: self.iterations as u32,
            m_cost: memory_cost as u32,
            lanes: self.parallelism,
            threads: self.parallelism,
            version: ARGON2_VERSION_13,
            allocate_cbk: None,
            free_cbk: None,
            flags: 0,
        };

        let context_ptr = &mut context as *mut Argon2_Context;
        let variant = self.variant as argon2_type;
        let return_code = unsafe { argon2_ctx(context_ptr, variant) };

        match check_return_code(return_code) {
            Ok(_) => {
                //println!("Hashed output: {:?}", u8_arr_to_i8_arr(&buffer[..]));
                Ok(buffer)
            }
            Err(m) => Err(Error::UnexpectedError(m)),
        }
    }
}

// TODO:: Need to redo this ??
fn check_return_code(
    return_code: argon2_sys::Argon2_ErrorCodes,
) -> std::result::Result<(), String> {
    match return_code {
        ARGON2_OK => Ok(()),

        argon2_sys::ARGON2_MEMORY_ALLOCATION_ERROR => Err("MemoryAllocationError".to_string()),

        argon2_sys::ARGON2_THREAD_FAIL => Err("ThreadError".to_string()),

        _ => {
            let err_msg_ptr = unsafe { argon2_error_message(return_code) };
            if err_msg_ptr.is_null() {
                return Err(format!(
                    "Unhandled error from argon2 api c lib call. Error code: {}",
                    return_code,
                ));
            }
            let err_msg_cstr = unsafe { CStr::from_ptr(err_msg_ptr) };
            let err_msg = err_msg_cstr.to_str().unwrap(); // Safe; see argon2_error_message
            Err(format!(
                "Unhandled error from argon2 api c lib call. Error code: {}. Error {}",
                return_code, err_msg
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Argon2Kdf, Kdf, VARIANT_ARGON2_D, VARIANT_ARGON2_ID};

    // Эталонные значения получены официальными биндингами референсной реализации Argon2
    // (argon2-cffi 25.1.0, крейт tools/kdbx-oracle), а не нашим кодом.
    //
    // Официальный вектор RFC 9106 через наш API недостижим: там salt 16 байт плюс secret и
    // associated data, а `transform_key` жёстко берёт salt 32 байта и передаёт secret/ad как
    // null (см. выше в этом файле). Поэтому вектор снят для нашей формы параметров.
    // Сам примитив против RFC 9106 проверяется тестами крейта `argon2` (появится в Step 10).

    const PASSWORD: [u8; 32] = [0x01; 32];
    const SALT: [u8; 32] = [0x02; 32];

    const MEMORY_8_MIB: u64 = 8 * 1024 * 1024;
    const ITERATIONS: u64 = 2;
    const PARALLELISM: u32 = 2;

    const EXPECTED_ARGON2D: &str =
        "c9bd6947c5082c4e2e634ea4d7863939e94b18b516505c372922f95df0ea5bb9";
    const EXPECTED_ARGON2ID: &str =
        "50b87226bb37ae4fb8d2ec86c5a944c4e361c7054f47a263df3a41911e56cba2";

    fn kdf_with_fixed_salt(variant: u32) -> Argon2Kdf {
        Argon2Kdf {
            salt: SALT.to_vec(),
            memory: MEMORY_8_MIB,
            iterations: ITERATIONS,
            parallelism: PARALLELISM,
            version: 19,
            variant,
        }
    }

    #[test]
    fn verify_argon2d_reference_vector() {
        let transformed = kdf_with_fixed_salt(VARIANT_ARGON2_D)
            .transform_key(PASSWORD.to_vec())
            .unwrap();
        assert_eq!(hex::encode(&transformed), EXPECTED_ARGON2D);
    }

    #[test]
    fn verify_argon2id_reference_vector() {
        let transformed = kdf_with_fixed_salt(VARIANT_ARGON2_ID)
            .transform_key(PASSWORD.to_vec())
            .unwrap();
        assert_eq!(hex::encode(&transformed), EXPECTED_ARGON2ID);
    }

    // Варианты должны давать разный результат: если параметр variant где-то потеряется,
    // оба теста выше могут остаться зелёными по совпадению только при одинаковых выходах.
    #[test]
    fn verify_argon2_variants_differ() {
        let d = kdf_with_fixed_salt(VARIANT_ARGON2_D)
            .transform_key(PASSWORD.to_vec())
            .unwrap();
        let id = kdf_with_fixed_salt(VARIANT_ARGON2_ID)
            .transform_key(PASSWORD.to_vec())
            .unwrap();
        assert_ne!(d, id, "Argon2d и Argon2id дали одинаковый результат");
    }

    // uuid_bytes должен соответствовать варианту — иначе KDBX-файл будет помечен не тем KDF
    #[test]
    fn verify_variant_uuids() {
        use crate::constants::uuid::{ARGON2_D_KDF, ARGON2_ID_KDF};
        assert_eq!(Argon2Kdf::variant_2d().uuid_bytes(), ARGON2_D_KDF);
        assert_eq!(Argon2Kdf::variant_2id().uuid_bytes(), ARGON2_ID_KDF);
    }
}
