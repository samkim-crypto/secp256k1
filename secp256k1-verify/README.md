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

## Compute Units (CU) Overhead

This library operates with zero allocations (`#![no_std]`) and avoids hidden
branching to minimize overhead.

The majority of the compute unit cost comes from the underlying native
`sol_secp256k1_recover` syscall, which consumes a flat baseline of
**25,000 CUs**.

For the standard use case of strict EVM verification (Keccak-256 hashing,
Ethereum address matching, and enforcing Low-S) the total cost is
approximately **25,316 CUs**.

### Configuration Modifiers

Depending on your builder configuration, you can calculate your exact overhead
by applying the following modifiers to the **25,316** CU baseline:

**Signature Malleability**

- **Strict (Enforce Low-S):** `Baseline`
- **Auto-Normalize S:** `+19 CUs` _(Mutates high-S signatures to low-S)_
- **Allow High-S:** `-5 CUs` _(Skips bounds checking entirely)_

**Message Hashing**

- **Keccak256Hasher:** `Baseline`
- **RawHasher (Pre-Hashed):** `-161 CUs` _(Bypasses the payload hash syscall)_

**Address Matching**

- **EvmAddress:** `Baseline`
- **RawPubkey (64-byte Match):** `-165 CUs` _(Bypasses the public key hash syscall)_

Because of overlapping compiler register optimizations and the hard physical floor
of the 25,000 CU recovery syscall, modifiers are not perfectly linear when combined.
Combining both `RawHasher` and `RawPubkey` yields a total combined savings of **-270
CUs** (rather than -326 CUs), resulting in the **25,046 CU** bare-minimum preset.

_(If utilizing a dynamic hasher like `Keccak256Hasher` or `Sha256Hasher`,
CU consumption will scale linearly at a rate of 1 CU per byte of the
message payload)._

## Extensibility via Traits

To maximize flexibility and remain `#![no_std]` compliant with zero
allocations, the verification pipeline relies on two core traits:
`MessageHasher` and `AddressMatcher`. This allows you to easily inject custom
cryptographic algorithms or identity derivations into the verification pipeline
without incurring performance overhead.

### 1. MessageHasher

This trait dictates how a dynamic message payload is hashed down to a 32-byte
scalar before public key recovery.

The library provides three built-in implementations:

- `Keccak256Hasher`: Applies the standard Keccak-256 algorithm (Default EVM
  behavior).
- `Sha256Hasher`: Applies the standard SHA-256 algorithm.
- `RawHasher`: A strict pass-through for messages that are already pre-hashed
  to exactly 32 bytes. This bypasses internal hashing overhead entirely.

**Implementing a Custom Hasher:**

```rust
use solana_secp256k1_verify::{MessageHasher, Secp256k1VerifyError};

pub struct MyCustomHasher;

impl MessageHasher for MyCustomHasher {
    fn hash(message: &[u8]) -> Result<[u8; 32], Secp256k1VerifyError> {
        // Custom hashing logic to return a 32-byte scalar
        // ...
    }
}
```

### 2. AddressMatcher

This trait defines how the recovered 64-byte uncompressed public key is matched
against your expected target identity or address format.

The library provides two built-in implementations:

- `EvmAddress`: Hashes the public key via Keccak-256 and strictly matches the
  20-byte suffix (Standard Ethereum EVM address derivation).
- `RawPubkey`: Performs a direct 64-byte comparison against a fully uncompressed
  public key.

**Implementing a Custom Address Matcher:**

```rust
use solana_secp256k1_verify::AddressMatcher;

pub struct CustomIdentityMatcher(pub [u8; 32]);

impl AddressMatcher for CustomIdentityMatcher {
    fn matches(&self, recovered_pubkey: &[u8; 64]) -> bool {
        // Custom address derivation and matching logic
        // ...
    }
}
```
