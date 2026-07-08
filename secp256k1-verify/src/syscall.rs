use crate::error::Secp256k1VerifyError;

#[repr(C)]
struct HashInput {
    pub ptr: *const u8,
    pub len: u64,
}

extern "C" {
    #[cfg(feature = "keccak")]
    fn sol_keccak256(vals: *const HashInput, val_len: u64, hash_result: *mut u8) -> u64;
    #[cfg(feature = "sha256")]
    fn sol_sha256(vals: *const HashInput, val_len: u64, hash_result: *mut u8) -> u64;
    fn sol_secp256k1_recover(
        hash: *const u8,
        recovery_id: u64,
        signature: *const u8,
        result: *mut u8,
    ) -> u64;
}

#[cfg(feature = "keccak")]
#[inline(always)]
pub fn keccak256(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
    let mut hash = [0u8; 32];
    let input = HashInput {
        ptr: message.as_ptr(),
        len: message.len() as u64,
    };

    let result = unsafe { sol_keccak256(&input as *const HashInput, 1, hash.as_mut_ptr()) };

    if result == 0 {
        Ok(hash)
    } else {
        Err(Secp256k1VerifyError::RecoveryFailed)
    }
}

#[cfg(feature = "sha256")]
#[inline(always)]
pub fn sha256(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
    let mut hash = [0u8; 32];
    let input = HashInput {
        ptr: message.as_ptr(),
        len: message.len() as u64,
    };

    let result = unsafe { sol_sha256(&input as *const HashInput, 1, hash.as_mut_ptr()) };

    if result == 0 {
        Ok(hash)
    } else {
        Err(Secp256k1VerifyError::RecoveryFailed)
    }
}

#[inline(always)]
pub fn secp256k1_recover(
    hash: &[u8; 32],
    recovery_id: u8,
    signature: &[u8; 64],
) -> Result<[u8; 64], Secp256k1VerifyError> {
    let mut pubkey = [0u8; 64];

    let result = unsafe {
        sol_secp256k1_recover(
            hash.as_ptr(),
            recovery_id as u64,
            signature.as_ptr(),
            pubkey.as_mut_ptr(),
        )
    };

    if result == 0 {
        Ok(pubkey)
    } else {
        Err(Secp256k1VerifyError::RecoveryFailed)
    }
}
