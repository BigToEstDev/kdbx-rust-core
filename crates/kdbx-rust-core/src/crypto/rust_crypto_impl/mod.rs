// Pure Rust crypto layer on RustCrypto crates (generation digest 0.11 / cipher 0.5).
// Replaces the former Botan (C++ FFI) implementation: no unsafe code, no C/C++ toolchain
// needed to build, same crates for desktop and mobile targets.
//
// Primitives are checked against spec vectors in crypto/mod.rs (NIST, RFC 8439, RFC 4231/2202)
// and against a foreign KDBX implementation in tests/foreign_fixtures.rs and
// tools/kdbx-oracle/verify_roundtrip.py.

mod block_cipher;
mod hash_functions;
mod key_cipher;
mod random;
mod stream_cipher;

pub use hash_functions::*;
pub use key_cipher::*;
pub use random::*;
pub use stream_cipher::ProtectedContentStreamCipher;

pub fn print_crypto_lib_info() {
    log::info!("The RustCrypto impl module is used for all encryptions and decryptions");
}
