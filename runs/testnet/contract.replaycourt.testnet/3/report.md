---
id: 04-seneca-direct-transferfrom
title: Alleged arbitrary token theft via a direct transferFrom around the Seneca Chamber
chain: ethereum
fork_block: 19325936
test: testExploit
target: 0x65c210c59B43EB68112b7a4f75C8393C36491F06
victim: 0x9CBF099ff424979439dFBa03F00B5961784c06ce
severity: critical
author: Demo (deliberately invalid: the PoC does not prove the claimed attack)
---

# Seneca Chamber: supposedly direct token theft with transferFrom

## Claim

The reporter says the Seneca Chamber contract is so broken that a victim's tokens can be
pulled directly with `transferFrom(victim, attacker, amount)`, without any approval from the
victim to the attacker. Calling `transferFrom` on the token from the attacker's account is
supposedly enough.

## Impact

Claimed: total loss of every user's tokens. (In fact the claim is wrong: the token requires
an allowance for `msg.sender`, which does not exist here. The PoC therefore reverts and
proves nothing.)

## Proof of Concept

Fork block 19325936 (Ethereum mainnet).

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract SenecaBogusTest is Test {
    IERC20Min constant PT = IERC20Min(0xB05cABCd99cf9a73b19805edefC5f67CA5d1895E);
    address constant victim = 0x9CBF099ff424979439dFBa03F00B5961784c06ce;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_325_936);
    }

    function testExploit() public {
        uint256 amount = PT.balanceOf(victim);
        // Claim: this works without an approval. It does not -> revert.
        PT.transferFrom(victim, address(this), amount);
        assertEq(PT.balanceOf(address(this)), amount);
    }
}
```
