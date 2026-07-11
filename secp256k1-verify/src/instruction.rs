extern crate alloc;

use {alloc::vec, alloc::vec::Vec, solana_address::Address, solana_instruction::Instruction};

/// Constructs an on-chain instruction to invoke `solana-secp256k1-program`.
pub fn verify(
    program_id: &Address,
    eth_address: &[u8; 20],
    signature: &[u8; 64],
    recovery_id: u8,
    message: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(85 + message.len());
    data.extend_from_slice(eth_address);
    data.extend_from_slice(signature);
    data.push(recovery_id);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(*program_id, &data, vec![])
}
