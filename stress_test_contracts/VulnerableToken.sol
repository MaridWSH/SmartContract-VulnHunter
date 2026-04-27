// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title VulnerableToken
 * @notice An ERC20 token with multiple vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
contract VulnerableToken is ERC20 {
    address public owner;
    mapping(address => bool) public blacklisted;
    
    // Centralization risk - single owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor(string memory name, string memory symbol, uint256 initialSupply) ERC20(name, symbol) {
        owner = msg.sender;
        _mint(msg.sender, initialSupply);
    }
    
    // Mint without cap - infinite mint vulnerability
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
    
    // Burn anyone's tokens
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }
    
    // Transfer with blacklist check but reentrancy vulnerability
    function transfer(address to, uint256 amount) public override returns (bool) {
        require(!blacklisted[msg.sender], "Sender blacklisted");
        require(!blacklisted[to], "Recipient blacklisted");
        
        // No reentrancy guard on ERC20 transfer
        _transfer(_msgSender(), to, amount);
        return true;
    }
    
    // Arbitrary blacklist
    function blacklistAddress(address account) external onlyOwner {
        blacklisted[account] = true;
    }
    
    // Unprotected function to change owner
    function changeOwner(address newOwner) external {
        // CRITICAL: No access control!
        owner = newOwner;
    }
    
    // Approve with race condition vulnerability
    function approve(address spender, uint256 amount) public override returns (bool) {
        // No protection against double-spend attack
        _approve(_msgSender(), spender, amount);
        return true;
    }
}
