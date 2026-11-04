---
title: <One line that names the contract and the bug>
chain: ethereum
fork_block: 19000000
test: testExploit
target: 0x0000000000000000000000000000000000000000
victim: 0x0000000000000000000000000000000000000000
severity: critical
author: <your name or handle>
---

# <The same title>

## Summary

<What is wrong, in a few sentences. Which function, which missing check.>

## Impact

<What an attacker gets, and who loses it.>

## Proof

Run `forge test` on a fork at the block above. The verifier runs exactly this test.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract ExploitTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
    }

    function testExploit() public {
        // Carry out the attack from this contract. The verifier reads the token transfers in
        // the trace, so the money must really move to this contract or to an attacker address.
        // Do not use vm.prank as the victim or vm.deal for the profit: that does not count.
    }
}
```

## Remediation

<How to fix it.>
