---
id: 05-fake-profit-deal-prank
title: "Alleged drain: the attacker ends up holding 1,000,000 USDC"
chain: ethereum
fork_block: 19000000
test: testExploit
target: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
victim: 0x28C6c06298d514Db089934071355E5743bf21d60
severity: critical
author: Demo (deliberately invalid: the "profit" is faked with cheatcodes)
---

# Alleged USDC drain

## Claim

An attacker could supposedly grab 1,000,000 USDC. As evidence, the PoC shows a USDC balance
of 1,000,000 for the attacker at the end and logs "Profit: 1000000 USDC".

## Impact

Claimed: critical total loss. (In fact the test only passes because the balance is set with
`deal()` and one transfer is triggered with `vm.prank` in the name of someone else's address.
There is no vulnerability and no real outflow of value.)

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IUSDC {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract FakeProfitTest is Test {
    IUSDC constant USDC = IUSDC(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    // Any well-funded address ("victim").
    address constant whale = 0x28C6c06298d514Db089934071355E5743bf21d60;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
    }

    function testExploit() public {
        // 1) Conjure the balance out of thin air:
        deal(address(USDC), address(this), 1_000_000e6);
        // 2) Additionally act in the name of the "victim" (not a real attack):
        vm.prank(whale);
        USDC.transfer(address(this), 1_000e6);

        emit log_named_uint("Profit: USDC", USDC.balanceOf(address(this)) / 1e6);
        assertGe(USDC.balanceOf(address(this)), 1_000_000e6);
    }
}
```
