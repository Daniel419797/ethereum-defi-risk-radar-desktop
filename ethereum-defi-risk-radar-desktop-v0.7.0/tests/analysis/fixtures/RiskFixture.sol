// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RiskFixture {
    address public owner;
    address public implementation;
    mapping(address => uint256) public balances;

    function route(address target, bytes calldata payload, uint256 amount) external {
        if (amount > 0) {
            balances[msg.sender] = amount;
        }
        target.call(payload);
    }

    function upgrade(address next) external {
        implementation = next;
        implementation.delegatecall(msg.data);
    }

    function loop(uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            balances[msg.sender] += i;
        }
    }
}
