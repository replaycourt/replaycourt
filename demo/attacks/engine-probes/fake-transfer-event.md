---
id: probe-fake-transfer-event
title: "Probe: PoC emits a fake ERC-20 Transfer event from its own contract"
chain: ethereum
fork_block: 19000000
test: testExploit
---

# Probe

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract FakeEventTest is Test {
    event Transfer(address indexed from, address indexed to, uint256 value);
    address constant whale = 0x28C6c06298d514Db089934071355E5743bf21d60;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
    }

    function testExploit() public {
        emit Transfer(whale, address(this), 1_000_000e18);
        emit log_named_uint("Profit", 1_000_000);
    }
}
```
