use {
    common::{first_offsets, signed_instruction, write_offsets},
    k256::ecdsa::Signature,
    solana_program_error::ProgramError,
    solana_secp256k1_program::{process_instruction, DATA_START, SIGNATURE_SERIALIZED_SIZE},
};

mod common;

#[test]
fn verifies_matching_signature() {
    let instruction = signed_instruction(&[b"hello secp256k1"]);
    // 0 accounts, pass the data, not in CPI (false)
    assert_eq!(process_instruction(0, &instruction, false), Ok(()));
}

#[test]
fn verifies_multiple_signatures() {
    let instruction = signed_instruction(&[b"hello secp256k1", b"second message"]);

    assert_eq!(process_instruction(0, &instruction, false), Ok(()));
}

#[test]
fn rejects_wrong_address() {
    let mut instruction = signed_instruction(&[b"hello secp256k1"]);
    let offsets = first_offsets(&instruction);
    instruction[usize::from(offsets.eth_address_offset)] ^= 1;

    assert_eq!(
        process_instruction(0, &instruction, false),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_corrupted_signature() {
    let mut instruction = signed_instruction(&[b"hello secp256k1"]);
    let offsets = first_offsets(&instruction);
    instruction[usize::from(offsets.signature_offset)] ^= 1;

    assert_eq!(
        process_instruction(0, &instruction, false),
        Err(ProgramError::InvalidArgument)
    );
}

#[test]
fn rejects_short_instruction() {
    assert_eq!(
        process_instruction(0, &[], false),
        Err(ProgramError::InvalidInstructionData)
    );
    assert_eq!(
        process_instruction(0, &[1], false),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn accepts_zero_signatures_only_when_data_has_no_payload() {
    assert_eq!(process_instruction(0, &[0], false), Ok(()));
    assert_eq!(
        process_instruction(0, &[0, 0], false),
        Err(ProgramError::InvalidInstructionData)
    );
}

#[test]
fn passes_supported_overflow_recovery_ids_to_recover() {
    for recovery_id in [2, 3] {
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        let offsets = first_offsets(&instruction);
        instruction[usize::from(offsets.signature_offset) + SIGNATURE_SERIALIZED_SIZE] =
            recovery_id;

        assert_eq!(
            process_instruction(0, &instruction, false),
            Err(ProgramError::InvalidArgument)
        );
    }
}

#[test]
fn rejects_invalid_recovery_ids() {
    for recovery_id in [4, 27, 28, 29, 30] {
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        let offsets = first_offsets(&instruction);
        instruction[usize::from(offsets.signature_offset) + SIGNATURE_SERIALIZED_SIZE] =
            recovery_id;

        assert_eq!(
            process_instruction(0, &instruction, false),
            Err(ProgramError::InvalidInstructionData)
        );
    }
}

#[test]
fn accepts_malleable_high_s_signature() {
    let mut instruction = signed_instruction(&[b"hello secp256k1"]);
    let offsets = first_offsets(&instruction);
    let signature_start = usize::from(offsets.signature_offset);
    let signature_end = signature_start + SIGNATURE_SERIALIZED_SIZE;
    let signature = Signature::from_slice(&instruction[signature_start..signature_end]).unwrap();
    let (r, s) = signature.split_scalars();
    let malleable_signature = Signature::from_scalars(r, -s).unwrap();

    assert!(malleable_signature.normalize_s().is_some());
    instruction[signature_start..signature_end].copy_from_slice(&malleable_signature.to_bytes());
    instruction[signature_end] ^= 1;

    assert_eq!(process_instruction(0, &instruction, false), Ok(()));
}

#[test]
fn rejects_out_of_bounds_offsets() {
    let mut instruction = signed_instruction(&[b"hello secp256k1"]);
    let mut offsets = first_offsets(&instruction);
    offsets.message_data_size = u16::MAX;
    write_offsets(&mut instruction[1..DATA_START], &offsets);

    assert_eq!(
        process_instruction(0, &instruction, false),
        Err(ProgramError::InvalidInstructionData)
    );
}
