#![no_std]

//! # Solana SECP256K1 Verify
//!
//! A fast, stateless, and highly configurable secp256k1 signature verification
//! library tailored for Solana smart contracts (`eBPF`).

pub mod address;
pub mod constants;
pub mod error;
pub mod hash;
mod verify;

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
mod syscall;

#[cfg(feature = "keccak")]
use crate::{address::EvmAddress, hash::Keccak256Hasher};

use {
    crate::{
        address::AddressMatcher,
        constants::{SIGNATURE_SERIALIZED_SIZE, UNCOMPRESSED_PUBKEY_COORDS_BYTES},
        error::Secp256k1VerifyError,
        hash::MessageHasher,
        verify::{recover_pubkey, verify_signature},
    },
    core::marker::PhantomData,
};

/// A stateless, zero-allocation configuration for secp256k1 verification.
///
/// # ECDSA Signature Malleability
/// In ECDSA, if a signature `(r, s)` is valid, the signature `(r, N - s)` is also
/// valid (where `N` is the order of the secp256k1 curve). This is known as signature
/// malleability.
///
/// To prevent transaction replay/malleability attacks, most networks (like Ethereum
/// via EIP-2) mandate that the `s` value must be in the lower half of the curve
/// order (`s <= N/2`).
///
/// This verifier defaults to strict Ethereum compliance (`enforce_low_s = true`),
/// but exposes builder methods to handle malleability in custom ways.
#[cfg(feature = "keccak")]
#[derive(Debug, Clone, Copy)]
pub struct Secp256k1Verifier<H = Keccak256Hasher, M = EvmAddress> {
    enforce_low_s: bool,
    normalize_s: bool,
    _phantom: PhantomData<(H, M)>,
}

#[cfg(not(feature = "keccak"))]
#[derive(Debug, Clone, Copy)]
pub struct Secp256k1Verifier<H, M> {
    enforce_low_s: bool,
    normalize_s: bool,
    _phantom: PhantomData<(H, M)>,
}

#[cfg(feature = "keccak")]
impl Default for Secp256k1Verifier<Keccak256Hasher, EvmAddress> {
    fn default() -> Self {
        Self::new()
    }
}

// Constructor functions
impl<H, M> Secp256k1Verifier<H, M> {
    /// Initializes a new configuration with strict defaults.
    pub fn new() -> Self {
        Self {
            enforce_low_s: true,
            normalize_s: false,
            _phantom: PhantomData,
        }
    }

    /// Disables malleability checks entirely.
    ///
    /// Both low-s and high-s signatures will be accepted. Use this only if your
    /// protocol is inherently immune to transaction malleability attacks.
    pub fn allow_high_s(mut self) -> Self {
        self.enforce_low_s = false;
        self.normalize_s = false;
        self
    }

    /// Auto-mutates a high-s signature to a low-s signature during execution.
    ///
    /// If a high-s signature is provided, this setting will silently flip it to its
    /// low-s counterpart (`N - s`) and flip the recovery ID (`v ^ 1`) before
    /// validation. This is useful for accepting slightly non-compliant signatures
    /// safely.
    pub fn auto_normalize_s(mut self) -> Self {
        self.enforce_low_s = false;
        self.normalize_s = true;
        self
    }
}

// Verification functions
impl<H: MessageHasher, M: AddressMatcher> Secp256k1Verifier<H, M> {
    pub fn verify_signature(
        &self,
        expected_address: M,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        recovery_id: u8,
        message: &[u8],
    ) -> Result<(), Secp256k1VerifyError> {
        verify_signature::<H, M>(
            expected_address,
            signature,
            recovery_id,
            message,
            self.enforce_low_s,
            self.normalize_s,
        )
    }

    pub fn recover_pubkey(
        &self,
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        recovery_id: u8,
        message: &[u8],
    ) -> Result<[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES], Secp256k1VerifyError> {
        recover_pubkey::<H>(
            signature,
            recovery_id,
            message,
            self.enforce_low_s,
            self.normalize_s,
        )
    }
}

#[cfg(all(test, feature = "keccak"))]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_default_state() {
        // Defaults should be strictly Ethereum compliant (No malleability)
        let verifier = Secp256k1Verifier::<Keccak256Hasher, EvmAddress>::new();
        assert!(verifier.enforce_low_s);
        assert!(!verifier.normalize_s);
    }

    #[test]
    fn test_verifier_allow_high_s() {
        // Should disable all checks
        let verifier = Secp256k1Verifier::<Keccak256Hasher, EvmAddress>::new().allow_high_s();
        assert!(!verifier.enforce_low_s);
        assert!(!verifier.normalize_s);
    }

    #[test]
    fn test_verifier_auto_normalize() {
        // Should disable strict enforcement, but enable mutation
        let verifier = Secp256k1Verifier::<Keccak256Hasher, EvmAddress>::new().auto_normalize_s();
        assert!(!verifier.enforce_low_s);
        assert!(verifier.normalize_s);
    }
}
