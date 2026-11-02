---
id: probe-dead-fork-url
title: "Probe: PoC forks from an unreachable URL"
chain: ethereum
fork_block: 19000000
test: testExploit
---

# Probe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract DeadForkTest is Test {
    function setUp() public {
        string memory u = string.concat("http://127.0.0.1:", "9/");
        vm.createSelectFork(u, 19_000_000);
    }

    function testExploit() public {
        emit log_named_uint("block", block.number);
    }
}
```
