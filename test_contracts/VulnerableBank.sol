// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // Reentrancy vulnerability
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        
        // Vulnerable: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // Integer overflow vulnerability (in Solidity < 0.8)
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    
    // Access control vulnerability
    function emergencyWithdraw() public {
        // Missing owner check - anyone can withdraw all funds
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
    
    // Unchecked external call
    function execute(address target, bytes memory data) public {
        (bool success, ) = target.call(data);
        // Missing success check - should be: require(success, "Call failed");
    }
    
    // Timestamp dependence
    function isLucky() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }
    
    receive() external payable {}
}
