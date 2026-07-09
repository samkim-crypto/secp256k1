use crate::error::Secp256k1VerifyError;

/// Defines the hashing algorithm applied to the message before signature recovery.
pub trait MessageHasher {
    /// Hashes a dynamic message down to a 32-byte scalar.
    fn hash(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError>;
}

/// Applies the `Keccak256` algorithm to the message (Standard Ethereum behavior).
#[cfg(feature = "keccak")]
pub struct Keccak256Hasher;

#[cfg(feature = "keccak")]
impl MessageHasher for Keccak256Hasher {
    #[inline(always)]
    fn hash(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
        Ok(solana_keccak_hasher::hash(message).to_bytes())
    }
}

/// Applies the `SHA256` algorithm to the message.
#[cfg(feature = "sha256")]
pub struct Sha256Hasher;

#[cfg(feature = "sha256")]
impl MessageHasher for Sha256Hasher {
    #[inline(always)]
    fn hash(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
        Ok(solana_sha256_hasher::hash(message).to_bytes())
    }
}

/// A strict pass-through `hasher` for messages that have already been hashed to
/// exactly 32 bytes.
pub struct RawHasher;

impl MessageHasher for RawHasher {
    #[inline(always)]
    fn hash(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
        if message.len() != 32 {
            return Err(Secp256k1VerifyError::InvalidMessageLength);
        }
        // Grab bytes immediately bypassing zero allocation
        Ok(unsafe { *(message.as_ptr() as *const [u8; 32]) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Secp256k1VerifyError;

    #[test]
    fn test_raw_hasher_success() {
        let message = [0xab; 32];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Ok(message));
    }

    #[test]
    fn test_raw_hasher_rejects_truncated_input() {
        // 31 bytes (too short)
        let message = [0xab; 31];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256k1VerifyError::InvalidMessageLength));
    }

    #[test]
    fn test_raw_hasher_rejects_extended_input() {
        // 33 bytes (too long - prevents silent truncation)
        let message = [0xab; 33];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256k1VerifyError::InvalidMessageLength));
    }

    #[test]
    fn test_raw_hasher_rejects_empty_input() {
        let message = [];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256k1VerifyError::InvalidMessageLength));
    }

    #[test]
    #[cfg(feature = "keccak")]
    fn test_keccak256_hasher() {
        let message = b"hello world";
        let hash = Keccak256Hasher::hash(message).unwrap();

        // Standard Keccak256 hash of "hello world"
        let expected =
            hex::decode("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad")
                .unwrap();

        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    #[cfg(feature = "sha256")]
    fn test_sha256_hasher() {
        let message = b"hello world";
        let hash = Sha256Hasher::hash(message).unwrap();

        // Standard SHA256 hash of "hello world"
        let expected =
            hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
                .unwrap();

        assert_eq!(hash.as_slice(), expected.as_slice());
    }
}
