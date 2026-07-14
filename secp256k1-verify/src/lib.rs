#![no_std]

//! # Solana SECP256K1 Verify
//!
//! A fast, stateless, and highly configurable secp256k1 signature verification
//! library tailored for Solana smart contracts (`eBPF`).

#[cfg(feature = "instruction")]
pub mod instruction;

#[cfg(feature = "verify")]
mod address;
#[cfg(feature = "verify")]
pub mod constants;
#[cfg(feature = "verify")]
mod error;
#[cfg(feature = "verify")]
mod hash;
#[cfg(feature = "verify")]
mod verifier;
#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "instruction")]
pub use instruction::{id, verify, ID};

#[cfg(feature = "verify")]
pub use {
    address::{AddressMatcher, RawPubkey},
    error::Secp256k1VerifyError,
    hash::{MessageHasher, RawHasher},
    verifier::Secp256k1Verifier,
};

#[cfg(all(feature = "verify", feature = "keccak"))]
pub use {address::EvmAddress, hash::Keccak256Hasher};

#[cfg(all(feature = "verify", feature = "sha256"))]
pub use hash::Sha256Hasher;
