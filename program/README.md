# solana-secp256k1-program

A standalone SBF (Solana Binary Format) program for on-chain secp256k1 ECDSA signature verification.

With the deprecation of native precompiles on Solana (SIMD-0568), this program provides a ready-to-use alternative.

## Deployment Address

This program is deterministically built and will be deployed to the following static address across all Solana clusters (Mainnet, Devnet, Testnet):

`SecKmPp2K9A9C7S8urKS7wjDvE3BL8B22XZHEuXVTRY`

## Overview

This program serves two primary purposes:

1. **Direct On-Chain Utility:** Protocols can invoke this program directly via
   Cross-Program Invocations (CPI) or sibling instruction introspection to verify
   standard Ethereum (EVM) signatures on-chain without writing their own verification
   logic.
2. **Reference Implementation:** The source code acts as a reference implementation
   demonstrating how to correctly parse instruction data and integrate the
   [`solana-secp256k1-verify`](../solana-secp256k1-verify) library into your own
   SBF programs.

For full usage instructions, instruction data layouts, and SDK builder helpers, please refer to the [Root Repository README](../README.md).
