use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2_v011::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};

// HMAC accepts keys of any length; the error branch exists only because KeyInit is generic.
fn new_hmac<M: Mac + KeyInit>(key: &[u8]) -> Result<M> {
    <M as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidCryptoInputLength("HMAC key"))
}

fn hmac_from_slices<M: Mac + KeyInit>(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    let mut mac = new_hmac::<M>(key)?;
    for v in data {
        mac.update(v);
    }
    Ok(mac.finalize().into_bytes().to_vec())
}

// Constant-time comparison: a plain `==` on the tag would leak the matching prefix length.
pub fn verify_hmac_sha256(key: &[u8], data: &[&[u8]], test_hash: &[u8]) -> Result<bool> {
    let mut mac = new_hmac::<Hmac<Sha256>>(key)?;
    for v in data {
        mac.update(v);
    }
    Ok(mac.verify_slice(test_hash).is_ok())
}

// Creates HMAC hash of data coming in slices
pub fn hmac_sha256_from_slices(key: &[u8], data: &[&[u8]]) -> Result<Vec<u8>> {
    hmac_from_slices::<Hmac<Sha256>>(key, data)
}

pub fn hmac_sha256_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices::<Hmac<Sha256>>(key, &[data])
}

pub fn hmac_sha512_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices::<Hmac<Sha512>>(key, &[data])
}

pub fn hmac_sha1_from_slice(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hmac_from_slices::<Hmac<Sha1>>(key, &[data])
}

fn hash_from_slices<D: Digest>(data: &[&[u8]]) -> Vec<u8> {
    let mut hasher = D::new();
    for v in data {
        hasher.update(v);
    }
    hasher.finalize().to_vec()
}

// The Result return type is kept for the callers: hashing itself cannot fail.

// Returns 32 bytes (256 bits) hash of input data 'a slice of vecs'
pub fn sha256_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let slices: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    Ok(hash_from_slices::<Sha256>(&slices))
}

// Returns 64 bytes (512 bits) hash of input data 'a slice of vecs'
pub fn sha512_hash_from_slice_vecs(data: &[&Vec<u8>]) -> Result<Vec<u8>> {
    let slices: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    Ok(hash_from_slices::<Sha512>(&slices))
}

// 32 bytes hash output of input data 'a vec of vecs'
pub fn sha256_hash_vec_vecs(data: &Vec<&Vec<u8>>) -> Result<Vec<u8>> {
    sha256_hash_from_slice_vecs(data)
}

pub fn sha256_hash_from_slice(data: &[u8]) -> Result<Vec<u8>> {
    Ok(hash_from_slices::<Sha256>(&[data]))
}

// HMAC and SHA are checked against RFC 4231 / RFC 2202 / NIST vectors in crypto/mod.rs.
