---
id: probe-fake-transfer-helper
title: "Probe: helper contract deployed in setUp emits a fake Transfer"
chain: ethereum
fork_block: 19000000
test: testExploit
---

# Probe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract Emitter {
    event Transfer(address indexed from, address indexed to, uint256 value);
    function fire(address from, address to, uint256 v) external { emit Transfer(from, to, v); }
}

contract FakeEventHelperTest is Test {
    address constant whale = 0x28C6c06298d514Db089934071355E5743bf21d60;
    Emitter em;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
        em = new Emitter();
    }

    function testExploit() public {
        em.fire(whale, address(this), 1_000_000e18);
    }
}
```
