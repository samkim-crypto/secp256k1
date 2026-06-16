//! Instructions and on-chain verification for the [`secp256k1` native program][np].
//!
//! [np]: https://solana.com/docs/core/programs/precompiles#verify-secp256k1-recovery
//!
//! This crate contains the on-chain processor that re-verifies secp256k1
//! signatures inside a Solana program, and re-exports the shared secp256k1
//! instruction types and client-side builders from the upstream SDK crate.
//!
//! _This crate exposes low-level cryptographic building blocks. Read this
//! documentation carefully and validate instruction layout assumptions in any
//! program that depends on signature verification for safety._
//!
//! The native secp256k1 program performs flexible verification of secp256k1
//! ECDSA signatures, as used by Ethereum. The shared API re-exported by this
//! crate mirrors that native instruction format so clients can build compatible
//! instructions, while this crate's processor verifies transaction-level
//! instructions and rejects cross-program invocations.
//!
//! The instruction is primarily designed for Ethereum interoperability, but it
//! is also useful for more general secp256k1 verification. It operates on
//! Ethereum addresses, which are Keccak hashes of secp256k1 public keys, and it
//! internally relies on secp256k1 key recovery. Ethereum addresses can be
//! derived from uncompressed secp256k1 public keys with
//! [`eth_address_from_pubkey`].
//!
//! Solana also exposes the lower-level [`solana_secp256k1_recover`] syscall for
//! direct public-key recovery. This crate does not expose raw recovery as a
//! program interface; it validates recovered keys against the expected Ethereum
//! address embedded in the instruction data.
//!
//! Typical use cases include:
//!
//! - Verifying Ethereum transaction signatures.
//! - Verifying Ethereum EIP-712 signatures.
//! - Verifying arbitrary secp256k1 signatures.
//! - Requiring multiple signatures over one or more messages.
//!
//! # Current crate structure
//!
//! This crate intentionally separates the shared client-facing wire definitions
//! from the on-chain verifier implementation:
//!
//! - The re-exported SDK surface provides types like [`SecpSignatureOffsets`],
//!   layout constants, Ethereum address helpers, and instruction builders.
//! - The `processor` module contains the on-chain verification logic.
//! - The `instruction_data` module contains parser helpers for the 11-byte offset records
//!   and instruction payload slices.
//!
//! The crate root remains thin and contains only documentation, re-exports, and
//! the Solana entry point.
//!
//! # How to use this program
//!
//! A typical transaction includes at least two logical steps:
//!
//! 1. A client constructs secp256k1-compatible instruction data containing the
//!    signature metadata and any inline payload bytes.
//! 2. The transaction includes this verifier as a top-level instruction, or a
//!    program inspects the transaction's native secp256k1 instruction and checks
//!    that the verified messages and addresses match its own expectations.
//!
//! In client code, the usual flow is:
//!
//! - Sign the Keccak-hashed messages with a secp256k1 ECDSA library.
//! - Build any custom instruction data that contains signatures, messages, or
//!   Ethereum addresses referenced by the secp256k1 offsets.
//! - Build the secp256k1 instruction data, specifying the instruction indexes
//!   and byte offsets of each signature, message, and Ethereum address.
//! - Submit all required instructions in one transaction.
//!
//! In on-chain code, the usual flow is:
//!
//! - Ensure the verifier is the expected program.
//! - Validate the number of signatures and the instruction layout.
//! - Check that the recovered signer addresses and signed messages match the
//!   program's own authorization rules.
//!
//! This crate's processor is intentionally stricter than the native precompile:
//! all offset references must point to the current instruction (index `0`). An
//! SBF program receives only its own instruction data, so supporting sibling
//! instruction references would require runtime support that Solana programs do
//! not currently have. The processor also rejects CPI by checking
//! `sol_get_stack_height()` before verifying instruction data.
//!
//! # Instruction data layout
//!
//! The instruction data mirrors the layout consumed by the native secp256k1
//! precompile:
//!
//! ```text
//! [num_signatures: u8]
//! [SecpSignatureOffsets × num_signatures]   (11 bytes each, little-endian)
//! [signature || recovery_id | eth_address | message …]   (payload, order flexible)
//! ```
//!
//! The payload bytes can be arranged however the client wants, as long as each
//! [`SecpSignatureOffsets`] record points at the correct byte ranges.
//!
//! The serialized offset structure has the following 11-byte layout:
//!
//! | index | bytes | type  | description |
//! |-------|-------|-------|-------------|
//! | 0     | 2     | `u16` | `signature_offset`: offset to the 64-byte compact signature. |
//! | 2     | 1     | `u8`  | `signature_instruction_index`: instruction index containing the signature. |
//! | 3     | 2     | `u16` | `eth_address_offset`: offset to the 20-byte Ethereum address. |
//! | 5     | 1     | `u8`  | `eth_address_instruction_index`: instruction index containing the address. |
//! | 6     | 2     | `u16` | `message_data_offset`: offset to the message bytes. |
//! | 8     | 2     | `u16` | `message_data_size`: message length in bytes. |
//! | 10    | 1     | `u8`  | `message_instruction_index`: instruction index containing the message. |
//!
//! All data references inside [`SecpSignatureOffsets`] must point into the same
//! instruction when processed by this crate; cross-instruction references are
//! rejected.
//!
//! # Signature malleability
//!
//! ECDSA signatures are malleable: given one valid signature, another distinct
//! but equally valid signature can be derived. This matters when applications
//! assume signatures have a unique representation.
//!
//! The underlying recovery syscall does not reject high-`S` signatures by
//! default. This crate normalizes supported high-`S` signatures before recovery
//! so that valid malleable forms still verify against the same signer address.
//! Programs that care about canonical forms should still define and enforce
//! their own policy at the application layer.
//!
//! # Additional security considerations
//!
//! Most programs should be conservative about what instruction shapes they
//! accept. Desirable checks often include:
//!
//! - The number of signatures is exactly what the program expects.
//! - Every instruction index field is exactly where the program expects the
//!   signature material to live.
//! - The signed messages are domain-separated and cannot be replayed across
//!   unrelated instructions or protocols.
//! - The verifier program ID is the expected one, so a malicious program cannot
//!   fake a successful verification path.
//!
//! # Errors
//!
//! Verification fails if any of the following are true:
//!
//! - Any signature is invalid.
//! - Any recovered signer does not match the provided Ethereum address.
//! - Any signature recovery id is outside `0..=3`.
//! - The instruction data is empty or truncated.
//! - The instruction advertises zero signatures but contains trailing payload.
//! - The offset table extends past the provided instruction data.
//! - Any referenced slice exceeds the instruction-data bounds.
//! - Any offset record references an instruction index other than `0`.

mod instruction;
mod instruction_data;
mod processor;

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub use instruction::sign_message;
pub use instruction::{
    eth_address_from_pubkey, eth_address_from_sec1_pubkey, SecpSignatureOffsets, DATA_START,
    HASHED_PUBKEY_SERIALIZED_SIZE, SECP256K1_PRIVATE_KEY_SIZE, SECP256K1_PUBKEY_SIZE,
    SECP256K1_UNCOMPRESSED_PUBKEY_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
    SIGNATURE_SERIALIZED_SIZE,
};
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
pub use instruction::{
    new_secp256k1_instruction_with_signature, try_new_secp256k1_instruction_with_signature,
};
pub use processor::process_instruction;

/// Program entrypoint for the version 2 instruction-data pointer interface.
#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entrypoint() -> u64 {
    use solana_transaction_context::{
        instruction::InstructionFrame,
        transaction::TransactionFrame,
        vm_addresses::{INSTRUCTION_TRACE_AREA, TRANSACTION_FRAME_ADDRESS},
    };

    // 1. Grab the Transaction Frame
    let tx_frame = &*(TRANSACTION_FRAME_ADDRESS as *const TransactionFrame);

    // 2. Map the Instruction Trace
    let instruction_trace = core::slice::from_raw_parts(
        INSTRUCTION_TRACE_AREA as *const InstructionFrame,
        tx_frame.total_number_of_instructions_in_trace as usize,
    );

    // 3. Grab the current Instruction Frame
    let current_frame = &instruction_trace[tx_frame.current_executing_instruction as usize];

    // 4. Extract clean data
    let num_accounts = current_frame.instruction_accounts.len() as usize;
    let ptr = current_frame.instruction_data.ptr() as *const u8;
    let len = current_frame.instruction_data.len() as usize;
    let instruction_data = core::slice::from_raw_parts(ptr, len);

    // If the caller is not u16::MAX, we are inside a CPI
    let in_cpi = current_frame.index_of_caller_instruction != u16::MAX;

    match process_instruction(num_accounts, instruction_data, in_cpi) {
        Ok(()) => solana_program_entrypoint::SUCCESS,
        Err(error) => error.into(),
    }
}
