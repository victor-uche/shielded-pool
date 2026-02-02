# ShieldedPool Protocol - Technical Documentation

## Overview

A non-custodial privacy engine for SIP-010 tokens on Stacks L2 implementing Zero-Knowledge transaction patterns with Bitcoin-compatible cryptography. Enables confidential asset transfers while maintaining audit capabilities through Merkle tree commitments.

## Key Components

1. **Merkle Tree Structure**

   - 20-layer depth (1,048,576 leaf capacity)
   - SHA-256 node hashing
   - Zero-value initialization (0x00...32)

2. **Core Mechanisms**

   - Deposit commitments with proof generation
   - Nullifier-based withdrawal proofs
   - Dynamic root updates
   - Dust protection (1M-1T satoshi range)

3. **Compliance Features**
   - Configurable token allowlists
   - Transaction amount thresholds
   - Principal-based ownership controls
   - Transparent root history

## Technical Specifications

- **Tree Parameters**

  ```clarity
  MERKLE-TREE-HEIGHT: u20
  ZERO-VALUE: 0x0000000000000000000000000000000000000000000000000000000000000000
  MIN-DEPOSIT-AMOUNT: u1,000,000
  MAX-DEPOSIT-AMOUNT: u1,000,000,000,000
  ```

- **State Model**

  - `deposits`: Commitment → (leaf-index, timestamp)
  - `nullifiers`: Nullifier → usage status
  - `merkle-tree`: (level, index) → node hash

- **Cryptographic Primitives**
  - SHA-256 hash combinations
  - Merkle proof verification (20-element proof)
  - Nullifier uniqueness checks

## Workflow Logic

### Deposit Sequence

1. User transfers tokens to contract
2. Generate cryptographic commitment
3. Insert into next available leaf position
4. Update Merkle tree nodes to root
5. Record commitment metadata

```clarity
(deposit commitment amount token)
```

### Withdrawal Sequence

1. Provide Merkle proof for commitment
2. Verify nullifier non-existence
3. Validate root consistency
4. Execute token transfer
5. Mark nullifier as used

```clarity
(withdraw nullifier root proof recipient token amount)
```

## Error System

| Code               | ID    | Description                   |
| ------------------ | ----- | ----------------------------- |
| ERR-NOT-AUTHORIZED | u1001 | Unauthorized admin action     |
| ERR-INVALID-AMOUNT | u1002 | Outside min/max deposit range |
| ERR-TREE-FULL      | u1007 | Exceeds 2²⁰ leaf capacity     |
| ERR-INVALID-PROOF  | u1006 | Cryptographic proof mismatch  |

## Administrative Controls

- `set-allowed-token`: Restrict to specific SIP-010 contracts
- `transfer-ownership`: Principal-based authority transfer
- Economic parameters (hardcoded):
  - Minimum deposit prevention
  - Maximum deposit safety limit

## Compliance Architecture

1. **Dust Mitigation**

   - Rejects deposits <1M units
   - Prevents micro-transaction spam

2. **Enterprise Features**

   - Token allowlisting
   - Principal-based access controls
   - Transparent root history

3. **Bitcoin Compliance**
   - SHA-256 proofs
   - UTXO-style nullifier model
   - Deterministic state transitions

## Audit Considerations

1. **Cryptographic Safety**

   - All hashes use Bitcoin-native SHA256
   - Zero-value initialization checks
   - Proof length validation (20 elements)

2. **State Integrity**

   - Separate deposit/nullifier maps
   - Immutable tree height post-deployment
   - Atomic root updates

3. **Administrative Security**
   - Owner privilege separation
   - No upgrade backdoors
   - Explicit error states

## Deployment Notes

1. Initializes with:

   - Zero-value root
   - Index counter at 0
   - Empty allowlist

2. Requires:
   - SIP-010 token pre-approval
   - Merkle proof generator integration
   - Nullifier management system
