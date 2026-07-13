# solana-secp256k1-program

With the deprecation of native precompiles on Solana (as outlined in SIMD-0568), support for the native `KeccakSecp256k11111111111111111111111111111` precompile is being removed.

To support protocols that rely on secp256k1 ECDSA signature verification, this repository provides a configurable BPF-compatible alternative. It is split into two core components:

1. **`solana-secp256k1-verify`**: A fast, stateless, zero-allocation library for in-program verification.
2. **`solana-secp256k1-program`**: A standalone SBF program to verify signatures on-chain.

## Migration Guide: Moving Away from Precompiles

If your protocol currently relies on the secp256k1 precompile, you can migrate to use this library and program in one of the following three approaches.

### 1. In-Program Verification via Library (Recommended)

The most efficient approach is to bundle the verification logic directly into your own program using the `solana-secp256k1-verify` crate.

The library utilizes a builder pattern to configure the verifier prior to execution. By default, the verifier adheres strictly to Ethereum (EIP-2) standards by enforcing low-s signatures to prevent malleability.

**Usage:**

```rust
use solana_secp256k1_verify::{Secp256k1Verifier, EvmAddress};

// 1. Initialize the stateless verifier with standard EVM defaults
let verifier = Secp256k1Verifier::default();

// 2. Wrap your expected 20-byte Ethereum address
let expected_address = EvmAddress([0xab; 20]);

// 3. Execute the verification pipeline
verifier.verify_signature(
expected_address,
&signature, // &[u8; 64]
recovery_id, // u8 (0, 1, 2, or 3)
&message // &[u8] dynamic message payload
)?;
```

_Note: To support legacy systems that produce high-s signatures, the verifier can be configured to automatically mutate high-s signatures into valid low-s signatures using `.auto_normalize_s()`. You can also completely disable malleability checks using `.allow_high_s()`._

### 2. Cross-Program Invocation (CPI)

If you prefer to offload the verification to a separate program, you can invoke `solana-secp256k1-program` via a Cross-Program Invocation (CPI).

**Instruction Data Layout:**
The program expects a minimum of 85 bytes of instruction data, formatted as follows:

- `[0..20]`: The 20-byte Ethereum address.
- `[20..84]`: The 64-byte signature.
- `[84]`: The 1-byte recovery ID.
- `[85..]`: The dynamic message payload.

You can easily construct this instruction using the provided SDK helper:

```rust
use solana_secp256k1_program::verify;
use solana_address::Address;

let instruction = verify(
program_id,
evm_address, // [u8; 20]
signature, // [u8; 64]
recovery_id, // u8
message, // &[u8]
);

## // Submit via invoke()
```

### 3. Instruction Introspection

Historically, many legacy applications relied on placing the precompile invocation alongside their program's invocation in the transaction, and using the `Instructions` sysvar to inspect the sibling instruction.

You can replicate this legacy pattern by pushing the `solana-secp256k1-program` instruction to the transaction instead of the old precompile. Your on-chain program will need to:

1. Load the `Instructions` sysvar.
2. Find the sibling instruction and verify that its `program_id` matches the new `solana-secp256k1-program`.
3. Parse its instruction data according to the layout described in the CPI section (`[0..20]` for address, `[20..84]` for signature, etc.).

## Performance & Compute Units (CU)

This repository is optimized for ultra-low compute unit consumption by leveraging stateless, zero-allocation architectures (`#![no_std]`) and direct native syscall pipelines.

A standard verification costs a flat baseline of **~25,000 CUs** driven by the underlying `sol_secp256k1_recover` syscall. Below is a quick performance profile:

| Strategy                 | Target Format                | Approximate CU Cost |
| :----------------------- | :--------------------------- | :------------------ |
| **Strict EVM (Default)** | 20-byte Ethereum Address     | `~25,316 CUs`       |
| **Auto-Normalize S**     | Malleable Signature Recovery | `~25,372 CUs`       |
| **Allow High-S**         | Unchecked Signature Recovery | `~25,348 CUs`       |

For automated benchmarking workflows or details on how config flags affect optimization, see the [solana-secp256k1-verify documentation](./solana-secp256k1-verify/README.md).
