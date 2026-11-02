---
id: probe-foreign-fork-url
title: "Probe: PoC forks from its own RPC URL built at runtime"
chain: ethereum
fork_block: 19000000
test: testExploit
---

# Probe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract ForeignForkTest is Test {
    function setUp() public {
        string memory u = string.concat("https://", "eth-mainnet.public.blastapi.io");
        vm.createSelectFork(u, 19_000_000);
    }

    function testExploit() public {
        emit log_named_uint("block", block.number);
    }
}
```
