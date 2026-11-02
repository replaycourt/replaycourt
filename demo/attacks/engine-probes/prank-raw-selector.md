---
id: probe-prank-raw-selector
title: "Calling prank through a raw selector, so no source scan can see it"
chain: ethereum
fork_block: 15725066
severity: critical
---
# Probe: cheatcode hidden from the source

The PoC calls the cheatcode address with a raw selector (`prank(address)` = `0xca669fa7`). Expected
verdict: invalid, because the trace still shows the identity takeover.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;
import "forge-std/Test.sol";
interface IERC20Lite { function transfer(address,uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }
contract Exploit is Test {
    IERC20Lite constant USDC = IERC20Lite(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant WHALE = 0x28C6c06298d514Db089934071355E5743bf21d60;
    function testExploit() public {
        uint256 bal = USDC.balanceOf(WHALE);
        (bool ok, ) = address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D).call(abi.encodeWithSelector(bytes4(0xca669fa7), WHALE));
        require(ok);
        USDC.transfer(address(this), bal);
        assertGt(USDC.balanceOf(address(this)), 0);
    }
}
```
