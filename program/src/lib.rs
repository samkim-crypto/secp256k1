#![cfg_attr(any(target_os = "solana", target_arch = "bpf"), no_std)]

use {
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, no_allocator,
        nostd_panic_handler, ProgramResult,
    },
    solana_secp256k1_verify::{address::EvmAddress, Secp256k1Verifier},
};
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
use {solana_instruction::Instruction, solana_pubkey::Pubkey};

no_allocator!();
nostd_panic_handler!();
lazy_program_entrypoint!(process_instruction);

pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    let instruction_data = context.instruction_data()?;

    // Validate the minimum instruction data length.
    // 20 (address) + 64 (signature) + 1 (recovery_id) = 85 bytes minimum.
    if instruction_data.len() < 85 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let eth_address: &[u8; 20] = instruction_data[0..20].try_into().unwrap();
    let signature: &[u8; 64] = instruction_data[20..84].try_into().unwrap();
    let recovery_id: u8 = instruction_data[84];
    let message: &[u8] = &instruction_data[85..];

    Secp256k1Verifier::default()
        .verify_signature(EvmAddress(*eth_address), signature, recovery_id, message)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    Ok(())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn verify(
    program_id: Pubkey,
    eth_address: [u8; 20],
    signature: [u8; 64],
    recovery_id: u8,
    message: &[u8],
) -> Instruction {
    let mut data = std::vec::Vec::with_capacity(85 + message.len());
    data.extend_from_slice(&eth_address);
    data.extend_from_slice(&signature);
    data.push(recovery_id);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(program_id, &data, std::vec![])
}
