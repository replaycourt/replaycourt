---
id: probe-revert-429
title: "Probe: PoC reverts with an RPC-looking message"
chain: ethereum
fork_block: 19000000
test: testExploit
---

# Probe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract DosTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
    }

    function testExploit() public {
        revert("429 Too Many Requests");
    }
}
```
