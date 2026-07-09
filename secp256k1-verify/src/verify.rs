use crate::{
    address::AddressMatcher,
    constants::{
        SCALAR_BYTES, SECP256K1_HALF_ORDER, SECP256K1_ORDER, SIGNATURE_SERIALIZED_SIZE,
        UNCOMPRESSED_PUBKEY_COORDS_BYTES,
    },
    error::Secp256k1VerifyError,
    hash::MessageHasher,
};

/// Recovers the uncompressed 64-byte public key from a signature and message.
pub(crate) fn recover_pubkey<H: MessageHasher>(
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    message: &[u8],
    enforce_low_s: bool,
    normalize_s: bool,
) -> Result<[u8; UNCOMPRESSED_PUBKEY_COORDS_BYTES], Secp256k1VerifyError> {
    if recovery_id > 3 {
        return Err(Secp256k1VerifyError::InvalidRecoveryId);
    }

    let s = &signature[SCALAR_BYTES..];
    let mut normalized_sig = [0u8; SIGNATURE_SERIALIZED_SIZE];
    let (active_sig, active_rec_id) = if enforce_low_s {
        if s > SECP256K1_HALF_ORDER.as_slice() {
            return Err(Secp256k1VerifyError::InvalidMalleableSignature);
        }
        (signature, recovery_id)
    } else if normalize_s {
        normalize_malleable_signature(signature, recovery_id, &mut normalized_sig)
    } else {
        (signature, recovery_id)
    };

    let message_hash = H::hash(message)?;

    let recovered =
        solana_secp256k1_recover::secp256k1_recover(&message_hash, active_rec_id, active_sig)
            .map_err(|_| Secp256k1VerifyError::RecoveryFailed)?
            .to_bytes();
    Ok(recovered)
}

/// Verifies a signature against an expected address.
///
/// This function handles message hashing, public key recovery, address matching,
/// and signature malleability enforcement in a single zero-allocation pass.
pub(crate) fn verify_signature<H: MessageHasher, M: AddressMatcher>(
    expected_address: M,
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    message: &[u8],
    enforce_low_s: bool,
    normalize_s: bool,
) -> Result<(), Secp256k1VerifyError> {
    let recovered_pubkey =
        recover_pubkey::<H>(signature, recovery_id, message, enforce_low_s, normalize_s)?;

    if !expected_address.matches(&recovered_pubkey) {
        return Err(Secp256k1VerifyError::AddressMismatch);
    }

    Ok(())
}

/// Mutates a high-s signature into a low-s signature by subtracting 's' from the
/// curve order.
pub(crate) fn normalize_malleable_signature<'a>(
    signature: &'a [u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    normalized_signature: &'a mut [u8; SIGNATURE_SERIALIZED_SIZE],
) -> (&'a [u8; SIGNATURE_SERIALIZED_SIZE], u8) {
    let s = &signature[SCALAR_BYTES..];
    if s > SECP256K1_HALF_ORDER.as_slice() && s < SECP256K1_ORDER.as_slice() {
        *normalized_signature = *signature;
        subtract_s_from_order(&mut normalized_signature[SCALAR_BYTES..]);
        (normalized_signature, recovery_id ^ 1)
    } else {
        (signature, recovery_id)
    }
}

/// Performs a big-endian, byte-by-byte subtraction of the scalar 's' from the
/// secp256k1 curve order.
pub(crate) fn subtract_s_from_order(s: &mut [u8]) {
    let mut borrow = 0u16;
    for (byte, order_byte) in s.iter_mut().rev().zip(SECP256K1_ORDER.iter().rev()) {
        let subtrahend = u16::from(*byte) + borrow;
        let minuend = u16::from(*order_byte);
        if minuend >= subtrahend {
            *byte = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            *byte = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::SCALAR_BYTES};

    #[test]
    fn test_subtract_s_from_order_boundary() {
        // Input: SECP256K1_ORDER - 1
        // Expected Output: 1 (in big-endian bytes)
        let mut s = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40, // <- 0
        ];

        subtract_s_from_order(&mut s);

        let mut expected = [0u8; 32];
        expected[31] = 0x01;

        assert_eq!(s, expected, "Subtraction failed borrow propagation");
    }

    #[test]
    fn test_normalize_malleable_signature_high_s() {
        let mut sig = [0u8; SIGNATURE_SERIALIZED_SIZE];

        // Fill 's' with the maximum possible value (SECP256K1_ORDER - 1)
        sig[SCALAR_BYTES..].copy_from_slice(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x40,
        ]);

        let original_rec_id = 0;
        let mut normalized_sig = [0u8; SIGNATURE_SERIALIZED_SIZE];

        let (active_sig, active_rec_id) =
            normalize_malleable_signature(&sig, original_rec_id, &mut normalized_sig);

        // Recovery ID should have flipped (0 ^ 1 = 1)
        assert_eq!(active_rec_id, 1);

        // The new 's' should be exactly 1
        assert_eq!(active_sig[63], 0x01);
        assert_ne!(active_sig, &sig); // Pointer should point to normalized
    }

    #[test]
    fn test_normalize_malleable_signature_low_s_unchanged() {
        let mut sig = [0u8; SIGNATURE_SERIALIZED_SIZE];
        sig[63] = 0x05; // A very low 's' value

        let mut normalized_sig = [0u8; SIGNATURE_SERIALIZED_SIZE];

        let (active_sig, active_rec_id) =
            normalize_malleable_signature(&sig, 0, &mut normalized_sig);

        assert_eq!(active_rec_id, 0); // Unchanged
        assert_eq!(active_sig, &sig); // Pointer should point to original
    }
}
