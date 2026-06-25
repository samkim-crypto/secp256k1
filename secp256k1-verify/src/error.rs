/// Errors that can occur during secp256k1 signature verification.
#[derive(Debug, PartialEq, Eq)]
pub enum Secp256k1VerifyError {
    /// The recovery ID must be between 0 and 3.
    InvalidRecoveryId,
    /// The mathematical recovery of the public key from the signature failed.
    RecoveryFailed,
    /// The recovered public key does not match the expected address.
    AddressMismatch,
    /// The signature has a high 's' value and the verifier enforces low-s signatures.
    InvalidMalleableSignature,
    /// The message provided to a strict hasher was not the correct length.
    InvalidMessageLength,
}
