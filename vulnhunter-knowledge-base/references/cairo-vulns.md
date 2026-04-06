# Cairo (Starknet) Vulnerability Reference

## Table of Contents
1. [Cairo Language Vulnerabilities](#1-cairo-language-vulnerabilities)
2. [Starknet-Specific Issues](#2-starknet-specific-issues)
3. [Access Control](#3-access-control)
4. [Arithmetic & Felt Operations](#4-arithmetic--felt-operations)
5. [Storage & State](#5-storage--state)
6. [Cross-Contract Interactions](#6-cross-contract-interactions)
7. [Upgradeability](#7-upgradeability)

---

## 1. Cairo Language Vulnerabilities

### 1.1 Felt252 Overflow Behavior
- `felt252` operates in a prime field (P = 2^251 + 17*2^192 + 1)
- Arithmetic wraps modulo P — NOT the same as uint256 overflow
- Subtraction of larger from smaller doesn't revert — wraps to a huge number
- Fix: Use explicit bounds checking, or `u256`/`u128` types where overflow should revert

### 1.2 Division in Field Arithmetic
- Division on felts is modular inverse — `a / b` gives `c` such that `b * c = a (mod P)`
- This is mathematically valid but NOT integer division
- `6 / 2 = 3` works as expected, but `7 / 2` does NOT give 3 — it gives a huge field element
- Fix: Use `u256` or `u128` for integer arithmetic, reserve felt252 for hashing/cryptography

### 1.3 Non-Deterministic Hints
- Cairo 0: Hints are Python code that runs off-chain — prover can supply any value
- If hint output isn't fully constrained by assertions, prover can cheat
- Cairo 1: Hints are more restricted but external function calls still need validation
- Fix: Every hint output must be constrained by verifiable assertions

### 1.4 Missing Range Checks
- Cairo VM doesn't automatically range-check values
- A felt252 value might be technically valid but semantically out of range
- Fix: Explicit `assert(value < MAX)` for all externally-influenced values

### 1.5 Unconstrained Outputs
- Functions that compute values without asserting correctness of results
- The prover can substitute arbitrary values if assertions are incomplete
- Fix: Assert all mathematical relationships between inputs and outputs

---

## 2. Starknet-Specific Issues

### 2.1 L1 ↔ L2 Message Vulnerabilities
- Messages between L1 (Ethereum) and L2 (Starknet) can be spoofed if not properly validated
- `from_address` in L1 → L2 messages must be verified
- L2 → L1 messages: ensure the L1 handler validates the L2 contract address
- Replay: L1 messages can potentially be consumed multiple times if nonce isn't tracked

### 2.2 Sequencer Centralization
- Starknet currently has a centralized sequencer
- Sequencer can: order transactions, censor transactions, extract MEV
- Check: Does the protocol assume fair ordering? Does it rely on timely inclusion?

### 2.3 Account Abstraction Quirks
- Starknet uses native account abstraction — all accounts are contracts
- `__validate__` and `__execute__` are separate phases
- Validation should be pure (no state changes) — but bugs here can be exploited
- Check: Can `__validate__` be tricked into approving malicious transactions?

### 2.4 Transaction Finality Assumptions
- Starknet transactions are not final until proven on L1
- Protocols assuming L2 finality before L1 proof are at risk during reorgs
- Fix: Distinguish between "accepted on L2" and "proven on L1" for critical operations

### 2.5 Nonce Management
- Starknet enforces sequential nonces per account
- Stuck nonce (failed transaction) blocks all subsequent transactions
- Check: Can an attacker grief a protocol by forcing nonce desync?

---

## 3. Access Control

### 3.1 Missing Caller Checks
- `get_caller_address()` returns the calling contract/account
- Not checking caller in sensitive functions = open access
- Fix: Store authorized addresses, check `get_caller_address()` against them

### 3.2 Constructor vs Initializer
- Cairo contracts have a `constructor` that runs once at deployment
- For upgradeable contracts: ensure initialization state can't be reset
- Fix: Boolean `initialized` flag, checked and set atomically

### 3.3 Component Access Control
- Cairo 1 components (traits + impls) — ensure component functions check access
- A component function embedded in a contract inherits that contract's storage
- But access control must still be explicitly implemented per function

### 3.4 Missing Zero-Address Checks
- Setting admin/owner to zero address (felt 0) locks out all admin functions
- Fix: Assert new admin != 0 in all admin-transfer functions

---

## 4. Arithmetic & Felt Operations

### 4.1 Felt Comparison Gotchas
- Comparing felts: `a < b` works on the field, but semantics differ from integers
- Values near `P` (the field prime) are "large" but represent "small negative" integers
- Fix: Use bounded integer types (u8, u16, u32, u64, u128, u256) for comparisons

### 4.2 Multiplication Overflow
- `u128 * u128` can overflow — Cairo 1 panics on overflow for integer types
- But `felt252 * felt252` wraps modulo P silently
- Fix: Use `u256` for intermediate multiplication results

### 4.3 Token Amount Calculations
- Same rounding/precision issues as other chains
- Additional risk: felt arithmetic can give unexpected results for division
- Fix: Use `u256` for all token amount math, multiply before divide

---

## 5. Storage & State

### 5.1 Storage Variable Collision
- Cairo storage uses hash-based addressing: `sn_keccak(variable_name)`
- Unlikely but possible: two variable names producing same hash
- Mappings use `h(sn_keccak(variable_name), key)` — check for collisions in nested mappings

### 5.2 Uninitialized Storage
- Storage defaults to 0/false/empty — same risks as Solidity
- Check: Is zero a dangerous default for any storage variable?

### 5.3 Storage Packing
- Cairo 1 packs multiple small values into a single felt252 storage slot
- Bugs in packing/unpacking can corrupt adjacent values
- Fix: Verify packing logic, especially for custom structs

---

## 6. Cross-Contract Interactions

### 6.1 Untrusted External Contract Calls
- `call_contract_syscall` to arbitrary addresses — same risk as Solidity's `call`
- Dispatcher patterns: ensure the target address is validated
- Fix: Whitelist target contracts or validate thoroughly

### 6.2 Callback Reentrancy
- Cairo/Starknet can have reentrancy through cross-contract calls
- Not as common as EVM due to account abstraction execution model
- But still possible: Contract A calls B, B calls back into A
- Fix: Reentrancy flags in storage, checks-effects-interactions

### 6.3 Library Calls
- `library_call_syscall` executes code in caller's context (like delegatecall)
- Ensure library contract is trusted and immutable
- Fix: Use declared class hashes, verify before calling

---

## 7. Upgradeability

### 7.1 Unsafe Upgrade Path
- `replace_class_syscall` replaces the contract's code
- If upgrade function isn't properly access-controlled, anyone can replace the code
- Fix: Strict access control, timelock, multi-sig for upgrades

### 7.2 Storage Layout Compatibility
- New implementation must be storage-compatible with the old one
- Adding/removing/reordering storage variables breaks existing state
- Fix: Only append new storage variables, never modify existing layout

### 7.3 Missing Upgrade Events
- No event emitted on upgrade — makes it hard to track contract changes
- Fix: Emit event with old class hash, new class hash, and caller
