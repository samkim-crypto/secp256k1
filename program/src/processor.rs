use {
    crate::instruction_data::{
        get_signature_fields, iter_signature_offsets, SignatureFields, SignatureOffsets,
    },
    solana_account_info::AccountInfo,
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_secp256k1_verify::{address::EvmAddress, Secp256k1Verifier},
};

/// Transaction index of the instruction whose data this program is verifying.
///
/// An SBF program only receives its own instruction data, so all offset fields
/// in `SecpSignatureOffsets` must reference index 0. Supporting other indices
/// would require a runtime change to expose sibling instruction data.
const CURRENT_INSTRUCTION_INDEX: u8 = 0;

pub(crate) fn in_cpi() -> bool {
    #[cfg(target_os = "solana")]
    {
        use solana_instruction::{syscalls::sol_get_stack_height, TRANSACTION_LEVEL_STACK_HEIGHT};

        unsafe { sol_get_stack_height() as usize > TRANSACTION_LEVEL_STACK_HEIGHT }
    }

    #[cfg(not(target_os = "solana"))]
    {
        false
    }
}

/// Parses `instruction_data` and verifies every secp256k1 signature it
/// describes, returning an error on the first failure.
pub(crate) fn verify_secp256k1_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entry point.
///
/// Expects no accounts and instruction data in the secp256k1 precompile
/// format. Returns [`ProgramError::InvalidArgument`] if invoked through CPI or
/// if any accounts are provided, or propagates errors from signature
/// verification.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if in_cpi() {
        return Err(ProgramError::InvalidArgument);
    }

    if !accounts.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_secp256k1_instruction(instruction_data)
}

/// Returns `true` when every offset field in `offsets` references the current
/// instruction (index 0) rather than a sibling instruction in the transaction.
fn references_current_instruction(offsets: &SignatureOffsets<'_>) -> bool {
    offsets.signature_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index() == CURRENT_INSTRUCTION_INDEX
}

/// Validates a single signature entry described by `offsets`.
///
/// Rejects offsets that reference instructions other than the current one,
/// then extracts the raw fields and delegates to [`verify_signature_fields`].
fn verify_signature(instruction_data: &[u8], offsets: &SignatureOffsets<'_>) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

/// Performs the signature check for one entry.
///
/// Hashes `fields.message` with Keccak-256, recovers the secp256k1 public key
/// from the compact signature, derives its Ethereum address, and compares it
/// against `fields.expected_address`. Returns [`ProgramError::InvalidArgument`]
/// if recovery fails or the addresses do not match.
fn verify_signature_fields(fields: &SignatureFields) -> ProgramResult {
    let verifier = Secp256k1Verifier::default().auto_normalize_s();
    let expected_address = EvmAddress(*fields.expected_address);
    verifier
        .verify_signature(
            expected_address,
            fields.signature,
            fields.recovery_id,
            fields.message,
        )
        .map_err(|_| ProgramError::InvalidArgument)?;

    Ok(())
}
