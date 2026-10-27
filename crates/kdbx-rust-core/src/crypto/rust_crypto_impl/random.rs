use crate::error::{Error, Result};

// All randomness comes from the OS CSPRNG. A failure is returned as an error: falling back to
// zeroed or predictable bytes would silently produce weak keys, salts and IVs.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| Error::RandomGenerationFailed(e.to_string()))
}

pub fn get_random_bytes<const N: usize>() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; N];
    fill_random(&mut buf)?;
    Ok(buf)
}

pub fn get_random_bytes_2<const N1: usize, const N2: usize>() -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((get_random_bytes::<N1>()?, get_random_bytes::<N2>()?))
}

pub fn get_random_bytes_3<const N1: usize, const N2: usize, const N3: usize>(
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    Ok((
        get_random_bytes::<N1>()?,
        get_random_bytes::<N2>()?,
        get_random_bytes::<N3>()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_random_bytes_lengths() {
        assert_eq!(get_random_bytes::<32>().unwrap().len(), 32);

        let (a, b) = get_random_bytes_2::<16, 12>().unwrap();
        assert_eq!((a.len(), b.len()), (16, 12));

        let (a, b, c) = get_random_bytes_3::<32, 16, 12>().unwrap();
        assert_eq!((a.len(), b.len(), c.len()), (32, 16, 12));
    }

    // Guards against a silent fallback to a constant buffer (the former Botan wrapper returned
    // zeros when the RNG call failed). Two independent 32-byte draws colliding is negligible.
    #[test]
    fn verify_random_bytes_not_constant() {
        let a = get_random_bytes::<32>().unwrap();
        let b = get_random_bytes::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, vec![0u8; 32]);
    }
}
