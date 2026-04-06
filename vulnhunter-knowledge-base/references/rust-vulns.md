# Rust (Solana / Anchor / CosmWasm) Vulnerability Reference

## Table of Contents
1. [Solana-Specific Vulnerabilities](#1-solana-specific-vulnerabilities)
2. [Anchor Framework Issues](#2-anchor-framework-issues)
3. [CosmWasm-Specific Vulnerabilities](#3-cosmwasm-specific-vulnerabilities)
4. [Common Rust Smart Contract Issues](#4-common-rust-smart-contract-issues)

---

## 1. Solana-Specific Vulnerabilities

### 1.1 Missing Account Validation
- **Signer checks**: Instruction doesn't verify the account is a signer
- **Owner checks**: Account owned by wrong program (e.g., system program vs your program)
- **Key checks**: Not verifying account pubkey matches expected PDA or known address
- **Writable checks**: Account marked writable when it shouldn't be, or vice versa
- Fix: Explicit checks on every account, or use Anchor's account constraints

### 1.2 Missing PDA Bump Validation
- PDA derived without canonical bump — attacker provides different bump, different address
- Multiple valid PDAs for same seeds if bump isn't constrained
- Fix: Always use `find_program_address` (canonical bump), store bump, verify on subsequent calls

### 1.3 Account Confusion / Type Confusion
- Passing Account A where Account B is expected — no discriminator check
- Raw Solana: All accounts are just byte arrays — program must validate type
- Fix: Discriminator bytes at start of account data (Anchor does this automatically)

### 1.4 Sysvar Spoofing
- Passing a fake sysvar account instead of the real one
- Pre-v1.8: Sysvars passed as accounts could be spoofed
- Fix: Use `sysvar::clock::Clock::get()` (on-chain getter) instead of account deserialization

### 1.5 Closing Accounts Improperly
- Account closed but not zeroed — can be "revived" in same transaction
- Lamports drained but data remains — program might still accept it
- Fix: Zero all data, transfer all lamports to recipient, assign owner to system program

### 1.6 Arithmetic Overflows
- Rust in release mode doesn't panic on overflow (wraps silently)
- Solana programs compile in release mode by default
- Fix: Use `checked_add`, `checked_sub`, `checked_mul`, `checked_div` everywhere

### 1.7 CPI Privilege Escalation
- Cross-Program Invocation (CPI) with wrong signer seeds
- Invoking a program with accounts that weren't intended to be passed
- Fix: Validate all CPI accounts, use minimal privileges

### 1.8 Reinitialization
- Program account can be initialized multiple times, resetting state
- Fix: `is_initialized` flag checked at start of initialize instruction

### 1.9 Duplicate Mutable Accounts
- Same account passed in two different mutable parameter positions
- Can lead to double-counting or conflicting writes
- Fix: Check all mutable accounts are distinct (Anchor `constraint` or manual check)

---

## 2. Anchor Framework Issues

### 2.1 Missing Constraints
- `#[account(mut)]` without additional constraints (seeds, has_one, constraint)
- Anchor validates the basics but business logic constraints are developer's responsibility
- Common misses: `has_one`, `seeds`, `bump`, `close`, `realloc`

### 2.2 `init` Without `payer` and `space`
- Incorrectly sized accounts can be exploited or cause panics
- Fix: Always specify `space` accurately, include discriminator (8 bytes) in calculation

### 2.3 Unchecked `remaining_accounts`
- `ctx.remaining_accounts` bypasses Anchor's account validation entirely
- Attacker can pass arbitrary accounts here
- Fix: Manually validate every remaining account (owner, key, signer, data)

### 2.4 PDA Authority Misuse
- Using PDA as authority but not properly validating the seeds/bump
- CPI calls with PDA signer: seeds must be for the correct PDA

### 2.5 Account Close Vulnerabilities
- `#[account(close = target)]` sends lamports to target and zeros data
- But within same transaction, account can be "reopened" via rent exemption
- Fix: Check account is still closed in subsequent instructions

---

## 3. CosmWasm-Specific Vulnerabilities

### 3.1 Missing Authorization in Execute Messages
- `ExecuteMsg` handlers not checking `info.sender` against stored admin/owner
- Any address can call privileged functions
- Fix: Check `info.sender` at top of every privileged handler

### 3.2 Unsafe Unwrap / Panic Paths
- `.unwrap()` on `None` or `Err` panics the contract — state changes NOT rolled back in submessages
- In Reply handlers, panic can leave inconsistent state
- Fix: Use `?` operator, proper error handling, avoid unwrap in all paths

### 3.3 Integer Overflow with Uint128/Uint256
- CosmWasm's `Uint128`/`Uint256` types panic on overflow
- This is DoS if attacker controls inputs that trigger overflow
- Fix: Use `checked_add`, `checked_sub` methods, handle errors gracefully

### 3.4 Reentrancy via Submessages
- Submessages (`SubMsg`) can call back into the same contract via `Reply`
- If state is inconsistent between message dispatch and reply handling, exploitable
- Fix: Update all state before dispatching submessages, validate state in Reply

### 3.5 Missing Funds Validation
- `info.funds` not checked — user sends wrong denomination or wrong amount
- Fix: Validate exact denomination and amount in `info.funds`

### 3.6 Storage Key Collisions
- Manual storage key construction can collide across different data types
- Fix: Use `cw-storage-plus` typed storage with unique prefixes

### 3.7 Migration Vulnerabilities
- `migrate()` function not checking authorization or version
- Attacker migrates to malicious code version
- Fix: Verify admin, validate version transitions

---

## 4. Common Rust Smart Contract Issues

### 4.1 Serialization/Deserialization Attacks
- Malformed account data causing panics during deserialization
- Borsh deserialization of attacker-controlled data
- Fix: Validate data length before deserializing, use safe deserialization

### 4.2 Logic Errors in State Machines
- State transitions not properly enforced — skip states, re-enter completed states
- Fix: Explicit state enum with valid transition table

### 4.3 Time-Based Vulnerabilities
- Using block time/slot for critical logic — validators have some control over block time
- Solana: `Clock::get().unix_timestamp` has ~1 second variance
- Cosmos: `env.block.time` controlled by validators within bounds

### 4.4 Rounding and Precision Loss
- Integer division truncation in token calculations
- `u64` operations losing precision for tokens with high decimals
- Fix: Multiply before dividing, use u128 for intermediate calculations

### 4.5 Missing Rent Exemption (Solana)
- Account falling below rent-exempt minimum gets garbage collected
- Attacker drains lamports to just below threshold
- Fix: Ensure accounts maintain rent exemption after all operations

### 4.6 Error Handling Suppression
- Matching on `Result` but ignoring `Err` cases silently
- `let _ = dangerous_operation()` discards errors
- Fix: Propagate all errors, log unexpected failures
