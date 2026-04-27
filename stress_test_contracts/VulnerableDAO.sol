// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableDAO
 * @notice A governance DAO with voting vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - FOR TESTING ONLY
 */
contract VulnerableDAO {
    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 startBlock;
        uint256 endBlock;
        bool executed;
        mapping(address => bool) hasVoted;
    }
    
    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower;
    uint256 public proposalCount;
    uint256 public votingDelay = 1;
    uint256 public votingPeriod = 40320; // ~1 week
    
    // Flash loan voting vulnerability
    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        proposalCount++;
        uint256 id = proposalCount;
        
        Proposal storage p = proposals[id];
        p.target = target;
        p.value = value;
        p.data = data;
        p.startBlock = block.number + votingDelay;
        p.endBlock = block.number + votingDelay + votingPeriod;
        
        return id;
    }
    
    // No checkpoint - flash loan can borrow and vote in same block
    function castVote(uint256 proposalId, bool support) external {
        Proposal storage p = proposals[proposalId];
        require(block.number >= p.startBlock, "Voting not started");
        require(block.number <= p.endBlock, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");
        
        uint256 votes = votingPower[msg.sender];
        
        // No validation that votingPower is snapshotted at proposal start
        if (support) {
            p.forVotes += votes;
        } else {
            p.againstVotes += votes;
        }
        
        p.hasVoted[msg.sender] = true;
    }
    
    // Execution before votes are tallied properly
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(block.number > p.endBlock, "Voting ongoing");
        require(!p.executed, "Already executed");
        
        // No quorum check!
        // No minimum participation requirement
        
        p.executed = true;
        (bool success, ) = p.target.call{value: p.value}(p.data);
        require(success, "Execution failed");
    }
    
    // Delegation without proper tracking
    function delegate(address delegatee) external {
        // Updates voting power in place without checkpoints
        votingPower[msg.sender] = 0;
        votingPower[delegatee] += votingPower[msg.sender]; // Logic error: adds 0
    }
    
    receive() external payable {}
}
