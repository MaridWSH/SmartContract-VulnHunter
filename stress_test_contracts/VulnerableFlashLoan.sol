// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableFlashLoan
 * @notice A flash loan provider with multiple critical vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
contract VulnerableFlashLoan {
    mapping(address => uint256) public balances;
    mapping(address => bool) public hasActiveLoan;
    
    uint256 public totalLiquidity;
    uint256 public fee = 9; // 0.09%
    address public owner;
    
    // Reentrancy vulnerability - no lock
    function flashLoan(uint256 amount, address target, bytes calldata data) external {
        uint256 initialBalance = address(this).balance;
        require(initialBalance >= amount, "Insufficient liquidity");
        
        // Transfer funds BEFORE checking repayment
        (bool success, ) = target.call{value: amount}(data);
        require(success, "Flash loan execution failed");
        
        // No reentrancy guard - vulnerable to reentrant calls
        uint256 repayment = amount + ((amount * fee) / 10000);
        require(address(this).balance >= initialBalance + (repayment - amount), "Flash loan not repaid");
        
        totalLiquidity += (repayment - amount);
    }
    
    // Access control vulnerability - no ownership check
    function setFee(uint256 newFee) external {
        // CRITICAL: No onlyOwner modifier
        fee = newFee;
    }
    
    // Integer overflow/underflow vulnerability (pre-0.8 behavior simulation)
    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value; // Can overflow
            totalLiquidity += msg.value; // Can overflow
        }
    }
    
    // Unchecked external call
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        
        // No check on external call success
        payable(msg.sender).call{value: amount}("");
    }
    
    // Timestamp dependence
    function isTradingHours() external view returns (bool) {
        // Vulnerable: relies on block.timestamp
        uint256 hour = (block.timestamp / 3600) % 24;
        return hour >= 9 && hour < 17;
    }
    
    // Delegatecall vulnerability
    function execute(address implementation, bytes calldata data) external {
        // CRITICAL: delegatecall to arbitrary address
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Execution failed");
    }
    
    // tx.origin authentication
    function privilegedOperation() external view returns (bool) {
        // Vulnerable: uses tx.origin instead of msg.sender
        require(tx.origin == owner, "Not authorized");
        return true;
    }
    
    receive() external payable {
        deposit();
    }
}
