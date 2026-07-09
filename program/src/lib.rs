#![no_std]

use {
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, ProgramResult,
    },
    solana_secp256k1_verify::{EvmAddress, Secp256k1Verifier},
};

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();
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
