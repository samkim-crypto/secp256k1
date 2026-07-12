# solana-secp256k1-verify

A configurable secp256k1 signature verification library tailored
specifically for Solana programs.

## Usage

The library utilizes a builder pattern to configure the verifier
prior to execution. By default, the verifier adheres strictly to
Ethereum (EIP-2) standards.

### Strict EVM Address Verification (Enforce Low-S)

By default, the `Secp256k1Verifier` applies Keccak-256 hashing, derives the 20-byte Ethereum address, and enforces low-s signatures to prevent malleability. High-s signatures will return an `InvalidMalleableSignature` error.

```rust
use solana_secp256k1_verify::{Secp256k1Verifier, EvmAddress};

// 1. Initialize the stateless verifier with standard EVM defaults
let verifier = Secp256k1Verifier::default();

// 2. Wrap your expected 20-byte Ethereum address
let expected_address = EvmAddress([0xab; 20]);

// 3. Execute the verification pipeline
verifier.verify_signature(
    expected_address,
    &signature,     // &[u8; 64]
    recovery_id,    // u8 (0, 1, 2, or 3)
    &message        // &[u8] dynamic message payload
)?;
```

### Handling Signature Malleability (Auto-Normalize S)

To support legacy systems that produce high-s signatures while
maintaining strict downstream compliance, the verifier can be
configured to automatically mutate high-s signatures into valid
low-s signatures prior to validation.

```rust
// Disables strict enforcement and silently normalizes malleable signatures
let verifier = Secp256k1Verifier::default().auto_normalize_s();

verifier.verify_signature(expected_address, &signature, recovery_id, &message)?;
```

### Allowing Malleable Signatures (Allow High-S)

If your protocol is inherently immune to transaction replay or malleability
attacks, you can configure the verifier to accept both low-s and high-s
signatures without mutation.

```rust
// Disables all malleability checks entirely
let verifier = Secp256k1Verifier::default().allow_high_s();

verifier.verify_signature(expected_address, &signature, recovery_id, &message)?;
```

### Pre-Hashed Messages & Custom Matchers

The verifier can be generically configured to accept alternative hashing
algorithms or address derivation logic. The following example demonstrates
strict 32-byte pre-hashed inputs validated against a raw 64-byte public key.

```rust
use solana_secp256k1_verify::{
    Secp256k1Verifier,
    RawHasher,
    RawPubkey
};

// Configure the verifier for strict 32-byte pre-hashed inputs and full pubkeys
let custom_verifier = Secp256k1Verifier::<RawHasher, RawPubkey>::new();

let expected_pubkey = RawPubkey(&[0x42; 64]);
let pre_hashed_message = &[0xff; 32];

custom_verifier.verify_signature(
    expected_pubkey,
    &signature,
    recovery_id,
    pre_hashed_message
)?;
```
