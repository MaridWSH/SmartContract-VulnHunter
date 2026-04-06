# Vyper Vulnerability Reference

## Table of Contents
1. [Vyper-Specific Language Issues](#1-vyper-specific-language-issues)
2. [Reentrancy in Vyper](#2-reentrancy-in-vyper)
3. [Access Control](#3-access-control)
4. [Arithmetic & Types](#4-arithmetic--types)
5. [External Calls & Interfaces](#5-external-calls--interfaces)
6. [Known Compiler Bugs](#6-known-compiler-bugs)

---

## 1. Vyper-Specific Language Issues

### 1.1 No Inheritance — Interface Compliance
- Vyper has no inheritance; interfaces are implemented manually
- Risk: Incomplete interface implementation, missing functions
- Check: All required interface functions present with correct signatures

### 1.2 Storage Layout Sensitivity
- Vyper lays out storage variables sequentially in declaration order
- Reordering variables in an upgrade breaks storage compatibility
- Fix: Never reorder, only append new variables at the end

### 1.3 Limited Modifier Support
- Vyper uses `@internal` functions instead of modifiers — ensure they're called consistently
- Easy to forget the auth check internal function on a new endpoint

### 1.4 Default Value Pitfalls
- All storage variables initialize to zero/empty — this is valid state
- Check: Does zero-value state create security issues? (e.g., address(0) as admin)

### 1.5 Missing `@nonreentrant` Decorator
- Vyper provides `@nonreentrant("lock_name")` — must be explicitly added
- Each lock name is independent — cross-function reentrancy possible with different lock names
- Fix: Use same lock name for all related functions

---

## 2. Reentrancy in Vyper

### 2.1 Raw Calls Without Reentrancy Guard
- `raw_call()` to external addresses without `@nonreentrant`
- Vyper doesn't prevent reentrancy by default (despite common misconception)

### 2.2 send() / raw_call() Ordering
- Same CEI pattern applies as Solidity
- State must be updated before any external call

### 2.3 Interface Calls
- Calling external contracts via interfaces (`Interface(addr).function()`)
- These are external calls — full reentrancy surface

### 2.4 Vyper Compiler Reentrancy Bug (CVE-2023-30629)
- Vyper versions 0.2.15, 0.2.16, 0.3.0 had a broken `@nonreentrant` decorator
- The reentrancy lock was not properly enforced in certain cross-function scenarios
- CRITICAL: Check compiler version — if affected, `@nonreentrant` provides FALSE security
- This bug was exploited in the Curve pool hacks (July 2023)

---

## 3. Access Control

### 3.1 Missing msg.sender Checks
- Same as Solidity — public/external functions without sender validation
- Vyper uses `msg.sender` identically to Solidity

### 3.2 Constructor (\_\_init\_\_) Issues
- `__init__` runs once at deployment — ensure it sets all critical state
- No re-initialization possible (Vyper doesn't have proxy patterns natively)

### 3.3 Default Function Exposure
- `__default__` function (fallback) — what happens when unexpected calldata arrives?
- Check: Can `__default__` be exploited or is it safely restricted?

---

## 4. Arithmetic & Types

### 4.1 Decimal Type Quirks
- Vyper has a `decimal` type (fixed-point) — limited precision (10 decimal places)
- Overflow behavior differs from uint256
- Check: Is decimal precision sufficient for the use case?

### 4.2 Integer Bounds
- Vyper integers are bounded by default and revert on overflow (unlike Solidity <0.8)
- But: shifts and bitwise operations may have unexpected behavior
- `convert()` between types can truncate silently in some versions

### 4.3 Division Behavior
- Vyper integer division truncates toward zero (same as Solidity)
- Same rounding attack vectors apply for financial calculations

---

## 5. External Calls & Interfaces

### 5.1 raw_call Return Values
- `raw_call()` returns success bool and data — must check both
- Common mistake: ignoring success value

### 5.2 Interface Assumptions
- Vyper interfaces assume the target implements the function correctly
- No guarantee the external contract behaves as expected
- Fix: Validate return values, handle failures

### 5.3 Static Call Violations
- `@view` functions should use `staticcall` — if implementation modifies state, it reverts
- But: read-only reentrancy is still possible through view functions

---

## 6. Known Compiler Bugs

### 6.1 Critical: Reentrancy Lock Failure (0.2.15 – 0.3.0)
- As noted above — the highest-impact Vyper compiler bug in history
- Any contract using `@nonreentrant` on these versions should be considered VULNERABLE

### 6.2 Compilation Differences
- Vyper compiler output can differ between versions for same source
- Always verify which compiler version produced the deployed bytecode

### 6.3 ABI Encoding Edge Cases
- Some Vyper versions had ABI encoding discrepancies with Solidity
- Cross-contract calls between Vyper and Solidity: verify ABI compatibility
