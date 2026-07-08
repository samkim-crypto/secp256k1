use crate::constants::UNCOMPRESSED_PUBKEY_COORDS_BYTES;

/// Defines the logic for matching a recovered public key against an expected
/// address format.
pub trait AddressMatcher {
    /// Returns true if the recovered 64-byte public key matches the expected address.
    fn matches(&self, recovered_pubkey: &[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES]) -> bool;
}

/// The standard size of an `EVM` address (20 bytes).
#[cfg(feature = "keccak")]
pub const ETH_ADDRESS_BYTES: usize = 20;

/// A standard Ethereum (`EVM`) 20-byte address.
#[cfg(feature = "keccak")]
pub struct EvmAddress(pub [u8; ETH_ADDRESS_BYTES]);

#[cfg(feature = "keccak")]
impl AddressMatcher for EvmAddress {
    #[inline(always)]
    fn matches(&self, pubkey: &[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES]) -> bool {
        eth_address_from_pubkey(pubkey) == self.0
    }
}

/// Derives a standard 20-byte Ethereum address from an uncompressed 64-byte public key.
#[cfg(feature = "keccak")]
pub fn eth_address_from_pubkey(
    pubkey: &[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES],
) -> [u8; ETH_ADDRESS_BYTES] {
    use crate::hash::{Keccak256Hasher, MessageHasher};

    let pubkey_hash = Keccak256Hasher::hash(pubkey).unwrap_or([0u8; 32]);
    let address_offset = 32 - ETH_ADDRESS_BYTES;
    // let address_offset = solana_keccak_hasher::HASH_BYTES - ETH_ADDRESS_BYTES;
    let mut addr = [0u8; ETH_ADDRESS_BYTES];
    addr.copy_from_slice(&pubkey_hash[address_offset..]);
    addr
}

pub struct RawPubkey<'a>(pub &'a [u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES]);

impl<'a> AddressMatcher for RawPubkey<'a> {
    fn matches(&self, pubkey: &[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES]) -> bool {
        pubkey == self.0
    }
}

#[cfg(all(test, feature = "keccak"))]
mod tests {
    use super::*;

    #[test]
    fn test_evm_address_matches_correct_pubkey() {
        // A dummy uncompressed public key (64 bytes)
        let pubkey = [0x42; 64];

        // Generate the expected hash manually
        let full_hash = solana_keccak_hasher::hash(&pubkey).to_bytes();
        let mut expected_address = [0u8; 20];
        expected_address.copy_from_slice(&full_hash[12..32]);

        // Test that our struct successfully matches it
        let evm_address = EvmAddress(expected_address);
        assert!(evm_address.matches(&pubkey));
    }

    #[test]
    fn test_evm_address_rejects_incorrect_pubkey() {
        let pubkey = [0x42; 64];

        // Use a completely random 20-byte address
        let evm_address = EvmAddress([0xab; 20]);

        assert!(!evm_address.matches(&pubkey));
    }
}
