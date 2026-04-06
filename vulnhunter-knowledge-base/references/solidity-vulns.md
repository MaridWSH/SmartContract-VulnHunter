# Solidity (EVM) Vulnerability Reference

## Table of Contents
1. [Reentrancy Variants](#1-reentrancy-variants)
2. [Access Control](#2-access-control)
3. [Integer & Arithmetic](#3-integer--arithmetic)
4. [External Calls & Interactions](#4-external-calls--interactions)
5. [Flash Loan Attacks](#5-flash-loan-attacks)
6. [Oracle & Price Feed](#6-oracle--price-feed)
7. [Proxy & Upgradeability](#7-proxy--upgradeability)
8. [Token Standards](#8-token-standards)
9. [Signature & Cryptography](#9-signature--cryptography)
10. [MEV & Frontrunning](#10-mev--frontrunning)
11. [Gas & DoS](#11-gas--dos)
12. [DeFi-Specific](#12-defi-specific)
13. [Data Handling & Storage](#13-data-handling--storage)
14. [Unsafe Logic Patterns](#14-unsafe-logic-patterns)
15. [Cross-Chain & L2 Compatibility](#15-cross-chain--l2-compatibility)
16. [Compiler & Language](#16-compiler--language)
17. [Code Quality & Hygiene](#17-code-quality--hygiene)

---

## 1. Reentrancy Variants

### 1.1 Classic / Single-Function Reentrancy
- State updated AFTER external call (ETH transfer, token transfer, callback)
- Pattern: `call{value: amount}("")` before state update
- Attack: Attacker's fallback/receive function recursively calls the vulnerable withdraw
  function, draining funds before balance is zeroed
- Example attack surface: Any function that sends ETH via `call` and updates balances after
- Fix: Checks-Effects-Interactions (CEI) pattern — update state BEFORE external call.
  Also use ReentrancyGuard (`nonReentrant` modifier)

### 1.2 Cross-Function Reentrancy
- Function A makes external call, attacker re-enters via Function B which reads stale state
- Example: `withdraw()` sends ETH, attacker re-enters via `transfer()` which reads
  the not-yet-zeroed balance and moves it to another address
- Common in: withdraw/balance patterns, multi-function state machines
- Fix: Global reentrancy lock across ALL related functions, not just single function

### 1.3 Cross-Contract Reentrancy
- Contract A calls Contract B, which calls back into Contract A (or Contract C that reads A's state)
- Especially dangerous with: callback patterns, ERC-777 hooks, flash loan callbacks
- Fix: Cross-contract reentrancy guards, careful call ordering

### 1.4 Read-Only Reentrancy
- External call allows re-entry into a VIEW function that returns stale state
- Other contracts reading this stale state make wrong decisions
- Example: Contract A has nonReentrant on `withdraw()` but not on its balance view function.
  During the callback in withdraw, attacker calls Contract B which reads A's stale
  balances and grants tokens based on inflated balance.
- Common in: Curve/Balancer LP token pricing, share price calculations
- Fix: Reentrancy guard on view functions that external contracts depend on

### 1.5 ERC-721 safeMint / safeTransfer Reentrancy
- OpenZeppelin's `_safeMint` and `_safeTransfer` call `onERC721Received` on the recipient
- This is an external call to an attacker-controlled contract — full reentrancy surface
- The function name "safe" is misleading — it's safe for the RECEIVER but creates
  reentrancy risk for the SENDER
- Fix: CEI pattern, nonReentrant modifier on mint/transfer functions

### 1.6 ERC-777 / ERC-1155 Callback Reentrancy
- `tokensReceived` (ERC-777) and `onERC1155Received` (ERC-1155) hooks enable reentrancy
- Any contract receiving these tokens is vulnerable if state isn't updated before transfer
- ERC-777 hooks registered via ERC-1820 registry can be set by token holder
- Fix: CEI pattern, or check for callback interfaces

---

## 2. Access Control

### 2.1 Missing Access Modifiers
- Public/external functions missing `onlyOwner`, `onlyRole`, or equivalent
- Critical for: admin functions, pause/unpause, parameter setters, fund recovery,
  interest rate changes, oracle updates
- Example: `function setInterestRate(uint256 _rate) public { interestRate = _rate; }`
  — anyone can call and change protocol parameters
- Fix: Add proper modifiers (onlyOwner, role-based with AccessControl)

### 2.2 Authorization via tx.origin
- Using `tx.origin` instead of `msg.sender` for auth — phishing vulnerable
- Attack: Attacker contract's fallback calls victim's `transferTo()`. Since
  `tx.origin` is the real user (who was tricked into interacting with attacker),
  the auth check passes
- Fix: Always use `msg.sender` for authorization, never `tx.origin`

### 2.3 Unprotected Initializers
- `initialize()` callable by anyone (missing `initializer` modifier)
- Especially dangerous in proxy patterns — attacker can initialize and become owner
- Fix: OpenZeppelin `Initializable`, constructor-based initialization

### 2.4 Default Visibility
- Functions without explicit visibility default to `public` in older Solidity versions
- State variables default to `internal` — verify this matches intent
- Modern compilers catch missing function visibility but may allow missing state
  variable visibility
- Fix: Always explicitly declare visibility for all functions and state variables

### 2.5 Privilege Escalation via Delegatecall
- Delegatecall to attacker-controlled address lets attacker run arbitrary code in caller's context
- Example: Proxy with `forward(address callee, bytes _data)` that delegatecalls to
  user-provided address — attacker passes a contract with `pwn()` that sets `owner = msg.sender`
- Delegatecall preserves msg.sender and msg.value but executes in caller's storage context
- Fix: Whitelist trusted contracts, never expose delegatecall to arbitrary addresses

### 2.6 Missing Two-Step Ownership Transfer
- Single-step `transferOwnership` can permanently lock out owner if wrong address is provided
- Fix: Two-step pattern (propose + accept) like OpenZeppelin Ownable2Step

---

## 3. Integer & Arithmetic

### 3.1 Overflow/Underflow (pre-0.8.0)
- Solidity <0.8.0 wraps silently on overflow/underflow
- Check: SafeMath usage, or compiler version ≥0.8.0
- Watch for: `unchecked` blocks in ≥0.8.0 that intentionally skip checks

### 3.2 Overflow Still Possible in ≥0.8.0
Even with built-in overflow protection, overflow can still occur in these cases:
- **Typecasting**: `uint256(258)` cast to `uint8` silently wraps to `2`
- **Shift operators**: `<<` and `>>` don't have overflow checks — `uint8(100) << 2` = 144 (overflow)
- **Inline assembly / Yul**: Low-level operations bypass overflow checks entirely
- **`unchecked` blocks**: Explicitly skip overflow checks for gas optimization
- Fix: Use SafeCast for downcasting, avoid shifts on bounded types, audit all `unchecked` blocks

### 3.3 Off-By-One Errors
- Incorrect boundary conditions — `<` vs `<=`, `>` vs `>=`, `length` vs `length - 1`
- Array iteration: `i < users.length - 1` skips the last element
- Comparison operators: Liquidation condition `if (ratio > 1e18) {} else { liquidate() }`
  incorrectly liquidates when ratio == 1e18 (should use `>=`)
- Fix: Carefully verify all boundary conditions match documentation/intent

### 3.4 Lack of Precision / Rounding Errors
- Solidity has no floating point — integer division truncates toward zero
- `(a * b) / c` vs `a * (b / c)` yield different results due to intermediate truncation
- Example: Fee calculation `amount / daysEarly * dailyFee` — 1.99 days rounds to 1 day,
  user pays half the intended fee
- Attack: Rounding in attacker's favor through carefully chosen small/specific amounts
- Fix: Multiply before dividing, use WAD (1e18) fixed-point math, ensure numerators are
  sufficiently larger than denominators

### 3.5 Division by Zero
- Solidity reverts on division by zero — this can be a DoS vector
- Check: Can denominator be manipulated to zero by an attacker?
- Fix: Validate denominator before division, ensure no path leads to zero denominator

### 3.6 Unsafe Casting
- Downcasting (uint256 → uint128/uint96/etc.) can silently truncate
- `SafeCast` library recommended for all narrowing conversions

---

## 4. External Calls & Interactions

### 4.1 Unchecked Return Values
- `address.call()` returns `(bool success, bytes data)` — MUST check success
- `address.send()` returns `bool` — MUST check return value
- `.transfer()` reverts on failure, but `.send()` and `.call()` do NOT
- Example: `winner.send(winAmount); paidOut = true;` — if send fails, paidOut is still
  set to true, allowing others to withdraw winner's funds
- Fix: Always `require(success)` after low-level calls, or use OpenZeppelin SafeERC20

### 4.2 Successful Call to Non-Existent Contract
- EVM considers calls to addresses with no code as successful
- Low-level `.call()` to a non-existent contract returns `success = true` with empty returndata
- Solidity high-level calls check `extcodesize` but low-level calls DO NOT
- Fix: Verify `to.code.length > 0` before low-level calls, or validate addresses at deployment

### 4.3 Forceful ETH Sending
- `selfdestruct(target)` forces ETH into any contract, bypassing receive/fallback
- Breaks contracts that rely on `address(this).balance` for logic
- Fix: Track balances via internal accounting, not `address(this).balance`

### 4.4 Unbounded Return Data (Gas Bomb)
- Solidity automatically copies ALL return data to memory, even if not requested
- Even `(bool success, ) = target.call{gas: 2500}(data)` copies full return data
  during the CALLER's execution frame, not the callee's
- Attacker can return huge data, causing exponential memory gas costs (OOG)
- Vulnerable flows: unstaking/undelegating callbacks, relayer patterns
- Fix: Use Yul/assembly for external calls with bounded return data size:
  `assembly { success := call(gas, target, 0, ..., returnData, 32) }`
- Reference: ExcessivelySafeCall library by Nomad, EigenLayer's DelegationManager pattern

### 4.5 Insufficient Gas Griefing
- In relayer/multisig patterns, forwarder provides just enough gas for outer call
  but insufficient gas for the inner sub-call
- The sub-call fails, but the outer transaction succeeds, marking it as "executed"
- Fix: Require minimum gas with `require(gasleft() >= _gasLimit)` in the called contract,
  or only allow trusted relayers

### 4.6 msg.value Reuse in Loops
- `msg.value` never changes during a transaction, even after sending ETH
- In loops: first iteration uses all ETH, subsequent iterations either drain contract
  balance or revert
- In batch operations: `require(msg.value == 1 ether)` can be passed once but the
  function called multiple times in a loop, buying N items for the price of 1
- Real-world exploit: Opyn Hack exploited msg.value reuse in payable multicalls
- Fix: Track spent amounts with internal accounting, don't use msg.value in loops

---

## 5. Flash Loan Attacks

### 5.1 Price Manipulation via Flash Loans
- Borrow large amount → manipulate spot price on DEX → exploit protocol using that price → repay
- Vulnerable: Any protocol using spot prices (balanceOf, getReserves) for valuation
- Fix: Use TWAP, Chainlink oracles, or multi-block price checks

### 5.2 Governance Flash Loan Attacks
- Flash borrow governance tokens → vote/propose → return tokens in same tx
- Fix: Snapshot-based voting, vote escrow, minimum holding period

### 5.3 Flash Mint Exploits
- If token supports flash minting, total supply can be temporarily inflated
- Breaks: Contracts using totalSupply() for percentage calculations in same tx

---

## 6. Oracle & Price Feed

### 6.1 Stale Price Data
- Chainlink: Not checking `updatedAt` timestamp or `answeredInRound`
- Fix: Require `block.timestamp - updatedAt < MAX_STALENESS`

### 6.2 Oracle Manipulation (Spot Prices)
- Using AMM spot price (reserves ratio) as oracle — trivially manipulable
- Fix: TWAP with sufficient window, or off-chain oracle (Chainlink, Pyth)

### 6.3 Multi-Oracle Disagreement
- Fallback oracle logic can be exploited if primary/secondary disagree
- Check: What happens when oracles give conflicting prices?

### 6.4 L2 Sequencer Downtime
- On L2s (Arbitrum, Optimism): sequencer goes down → stale prices
- Fix: Check Chainlink L2 sequencer uptime feed

### 6.5 Decimal Mismatch
- Different oracles return different decimal precision
- Mixing 8-decimal Chainlink feeds with 18-decimal token amounts without normalization

---

## 7. Proxy & Upgradeability

### 7.1 Storage Collision
- Proxy and implementation using same storage slots for different variables
- Fix: EIP-1967 standard storage slots, careful inheritance ordering

### 7.2 Function Selector Clash
- Proxy admin functions colliding with implementation function selectors
- Fix: Transparent proxy pattern or UUPS with proper selector checks

### 7.3 Uninitialized Implementation
- Implementation contract not initialized — attacker calls initialize directly
- Then `selfdestruct` on implementation breaks all proxies
- Fix: Initialize in constructor OR use `_disableInitializers()`

### 7.4 UUPS Missing Upgrade Auth
- `_authorizeUpgrade()` not properly restricted — anyone can upgrade
- Fix: Ensure onlyOwner or equivalent on upgrade authorization

---

## 8. Token Standards

### 8.1 ERC-20 Quirks
- Fee-on-transfer tokens: received amount < sent amount
- Rebasing tokens: balances change without transfers
- Return-value inconsistency: Some don't return bool (USDT)
- Double-spend on approval: approve(spender, newAmount) race condition
- Fix: SafeERC20, measure balance before/after, approve(0) then approve(n)

### 8.2 ERC-721 / ERC-1155
- `safeTransferFrom` triggers callbacks — reentrancy vector (see Section 1.5)
- `onERC721Received` / `onERC1155Received` return value must be checked
- Batch operations: unbounded loops can hit gas limit

### 8.3 ERC-777
- Hooks on send AND receive — powerful reentrancy surface
- Registered hooks via ERC-1820 registry can be set by token holder

### 8.4 Inadherence to Standards
- Contracts claiming ERC-20 compliance but missing return values, events, or functions
- Can break composability with other protocols expecting standard behavior
- Fix: Verify full standard compliance, use interface checks

---

## 9. Signature & Cryptography

### 9.1 Signature Replay
- Missing nonce → same signature reusable across transactions
- Missing chain ID → replayable across chains (especially after forks)
- Missing contract address → replayable across contracts
- Fix: Include nonce + chain ID + contract address in signed message hash.
  Store processed message hashes to prevent reuse. Never include the signature
  itself in the hash (see malleability)

### 9.2 Signature Malleability
- ECDSA signatures (r, s) have a complementary form: if (r, s) is valid, so is (r, -s mod n)
- Due to elliptic curve x-axis symmetry, attacker can produce second valid signature
  WITHOUT knowing the private key
- Breaks: Systems that track "used signatures" — attacker creates a modified but valid
  signature that bypasses the used-signature check
- Fix: Restrict s to lower half of curve (OpenZeppelin ECDSA library does this).
  Don't use raw signature bytes as unique identifiers — use the message hash instead

### 9.3 ecrecover Returns address(0)
- Invalid signatures (e.g., v != 27 && v != 28) return `address(0)` instead of reverting
- If unset storage variables (owner, admin) default to address(0), attacker can
  forge signatures that validate against these uninitialized addresses
- Fix: `require(recoveredAddress != address(0))` after every ecrecover call

### 9.4 EIP-712 Domain Separator Issues
- Hardcoded domain separator breaks after chain fork
- Fix: Compute dynamically or cache with chain ID check

### 9.5 Hash Collision with abi.encodePacked
- `abi.encodePacked()` with multiple variable-length arguments doesn't include boundaries
- `abi.encodePacked("a", "bc") == abi.encodePacked("ab", "c")` — identical hash!
- `abi.encodePacked([addr1, addr2], [addr3])` == `abi.encodePacked([addr1], [addr2, addr3])`
- Attack: In signature verification, attacker rearranges elements between arrays
  to produce same hash, bypassing authorization
- Fix: Use `abi.encode()` instead (includes length prefixes), or use only fixed-length
  types, or ensure at most one dynamic type argument

---

## 10. MEV & Frontrunning

### 10.1 Transaction-Ordering Dependence
- Mempool is public — anyone can see pending transactions before execution
- Generalized frontrunning bots scan for profitable, replicable transactions
- "Ethereum is a Dark Forest" — any profitable transaction can be frontrun
- Vulnerable: auctions, token approvals, DEX trades, liquidations, any first-come-first-served
- Fix: Commit-reveal schemes, private mempools (Flashbots), slippage protection

### 10.2 Sandwich Attacks
- AMM swaps without slippage protection
- Fix: Minimum output amount parameter, deadline parameter

### 10.3 Commit-Reveal Bypass
- If reveal phase doesn't properly validate against commit, or commit is predictable

---

## 11. Gas & DoS

### 11.1 DoS with Block Gas Limit / Unbounded Loops
- Iterating over dynamic arrays that can grow → eventual gas limit
- Even without malicious intent: too many users in a payment array
- Attack: Attacker creates many small positions to make batch operations exceed gas limit
- Block stuffing: Attacker fills blocks with high-gas-price txs to delay time-sensitive operations
  (used in Fomo3D exploit to win jackpot by blocking others)
- Fix: Pull-over-push payment pattern, pagination, allow multi-block operations

### 11.2 DoS with Unexpected Revert
- Sending ETH to a contract with reverting fallback blocks the entire function
- Example: Auction where highest bidder is a contract that reverts on receive — no one
  can ever outbid them because refund to current leader fails
- Iterating over users: one failing send reverts the entire loop
- Also caused by: unexpected overflow reverts in checked math, division by zero,
  unexpected balance changes via selfdestruct/force-send
- Fix: Pull pattern (users withdraw themselves), handle failures gracefully per-iteration

### 11.3 Griefing via Revert
- Contracts that must send ETH to recipient — recipient reverts in receive()
- Fix: Pull pattern, use `call` with failure handling, or WETH

### 11.4 External Call in Loop
- One failing call reverts entire loop
- Fix: Try/catch per iteration, or pull pattern

---

## 12. DeFi-Specific

### 12.1 First Depositor / Vault Inflation Attack
- First depositor can manipulate share price by donating tokens to vault
- Subsequent depositors get 0 shares due to rounding
- Fix: Virtual shares/assets (ERC-4626 mitigation), minimum first deposit, dead shares

### 12.2 Sandwich on Yield Harvests
- Attacker deposits before harvest, claims yield, withdraws immediately
- Fix: Time-weighted yield distribution, harvest delay

### 12.3 Liquidation Manipulation
- Manipulate price to trigger liquidation, then buy collateral at discount
- Self-liquidation for profit if incentive exceeds loss

### 12.4 Interest Rate Manipulation
- Utilization-based rates can be manipulated by large borrow/repay in same block
- Affects: Variable rate protocols, interest-bearing tokens

---

## 13. Data Handling & Storage

### 13.1 Write to Arbitrary Storage Location
- Dynamic arrays: if attacker controls array length, they can compute storage slot
  collisions and overwrite arbitrary storage (including owner)
- Array underflow trick (pre-0.6.0): underflow array length to get write access to
  entire storage space
- Fix: Bounds checking on all array operations, validate indices, use mappings where possible
- Reference: Ethernaut "Alien Codex" challenge

### 13.2 Uninitialized Storage Pointers (pre-0.5.0)
- Local struct/array variables without explicit `memory` keyword default to `storage`
- Uninitialized storage pointer overwrites slot 0, slot 1, etc. — can corrupt owner,
  balances, or other critical state
- Note: Solidity ≥0.5.0 compiler rejects this, but check for older contracts

### 13.3 Unencrypted Private Data On-Chain
- `private` keyword only prevents other contracts from reading — all on-chain data is
  publicly visible via `eth_getStorageAt`
- Passwords, secret numbers, commit values stored in plain storage can be read by anyone
- Fix: Commit-reveal schemes, zero-knowledge proofs, never store secrets in storage

---

## 14. Unsafe Logic Patterns

### 14.1 Weak Randomness from Chain Attributes
- Using `block.timestamp`, `blockhash`, `block.difficulty`/`prevrandao` for randomness
- All chain data is deterministic and publicly visible — attacker can predict or
  replicate the "random" value in the same block
- Attack: Attacker contract computes the same "random" number using identical block
  attributes and always wins
- Fix: Use Chainlink VRF or other verifiable random function oracle

### 14.2 Asserting Contract from Code Size
- Checking `msg.sender.code.length == 0` to assert EOA is bypassable
- During constructor execution, `extcodesize` returns 0 — contract can call your
  function from its constructor and bypass the check
- Fix: Cannot reliably distinguish EOA from contract on-chain. Use `msg.sender == tx.origin`
  (has its own risks) or redesign logic to not depend on caller type

### 14.3 Timestamp Dependence
- Post-merge: validators set block timestamp (must be > parent, within bounds)
- Pre-merge: miners could manipulate within ~15 second window
- Safe for: approximate time comparisons, long-duration timelocks
- Unsafe for: randomness, precise time-critical logic, short-window auctions
- Fix: Don't use for randomness, ensure time-dependent logic tolerates variance

---

## 15. Cross-Chain & L2 Compatibility

### 15.1 Unsupported Opcodes Across Chains
- `PUSH0` (introduced in Solidity 0.8.20 / Shanghai) not supported on all L2s
- Compile with Solidity <0.8.20 or check opcode support on target chain
- Use `cast call --rpc-url $RPC --create 0x5f` to test PUSH0 support

### 15.2 zkSync Era Specific Issues
- `CREATE`/`CREATE2` work differently — compiler must know bytecode in advance
- Dynamic bytecode creation via assembly doesn't work
- `.transfer()` limited to 2300 gas — can permanently lock funds if recipient
  needs more gas (Gemholic incident: 921 ETH locked)
- Fix: Use `call` instead of `transfer`, test deployments on target L2

### 15.3 Cross-Chain Message Spoofing
- L1 ↔ L2 messages must validate sender address on both sides
- Bridge replay attacks: same message consumed multiple times if nonce not tracked
- Fix: Validate `from_address` in all cross-chain message handlers

---

## 16. Compiler & Language

### 16.1 Known Compiler Bugs
- Check the Solidity bug list for the pragma version used
- Notable: ABI encoder v2 bugs (<0.8.14), optimizer bugs
- Floating pragma (`^0.8.0`) may compile with buggy versions

### 16.2 Outdated Compiler Version
- Old compilers miss security features and contain known bugs
- Fix: Use latest stable compiler version, pin pragma precisely

### 16.3 Deprecated Functions
- `suicide()` → `selfdestruct()`, `sha3()` → `keccak256()`
- `callcode()` → `delegatecall()`, `throw` → `revert()`/`require()`
- `msg.gas` → `gasleft()`, `constant` → `view`
- Fix: Replace all deprecated function calls

### 16.4 Storage Layout in Assembly
- Inline assembly accessing storage must account for variable packing
- `sload`/`sstore` operate on full 32-byte slots

### 16.5 Dirty Bits / Memory Safety
- Assembly blocks may leave dirty high bits in memory
- `calldataload` past calldata length returns zeros — exploitable if not expected

### 16.6 Incorrect Constructor Name (pre-0.4.22)
- Before Solidity 0.4.22, constructors used the contract name as function name
- Typo in constructor name creates a public function anyone can call
- Fix: Use `constructor()` keyword (Solidity ≥0.4.22)

---

## 17. Code Quality & Hygiene

### 17.1 Shadowing State Variables
- Derived contracts declaring variables with same name as parent contract variables
- The derived variable shadows the parent — reads/writes go to different storage slot
- Fix: Use unique names, enable compiler warnings

### 17.2 Incorrect Inheritance Order
- Solidity C3 linearization: order of inheritance affects which function implementation
  is used when multiple parents define the same function
- Fix: Order from "most base-like" to "most derived"

### 17.3 Assert Violation
- `assert()` should only be used for invariants that should NEVER be false
- `assert` consumes all remaining gas (unlike `require`)
- If assert can be triggered by user input, it's a gas-draining DoS vector
- Fix: Use `require()` for input validation, `assert()` only for internal invariants

### 17.4 Requirement Violation
- `require()` with incorrect conditions — too strict blocks legitimate use,
  too loose allows exploits
- Fix: Carefully validate all require conditions match intended invariants

### 17.5 Unused Variables
- Unused variables waste gas and indicate logic errors
- A variable declared but never used may mean a code path is incomplete
- Fix: Remove unused variables, investigate if they indicate missing logic

### 17.6 Floating Pragma
- `pragma solidity ^0.8.0;` allows compilation with any 0.8.x version
- Different compiler versions may have different behavior or bugs
- Fix: Pin exact version: `pragma solidity 0.8.20;`
