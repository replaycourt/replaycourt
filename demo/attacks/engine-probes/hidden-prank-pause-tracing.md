---
id: probe-hidden-prank
title: "Hiding the prank from the trace with vm.pauseTracing"
chain: ethereum
fork_block: 15725066
severity: critical
---
# Probe: hiding a cheatcode from the trace

The PoC tries to keep `vm.prank` out of the trace the engine reads. Expected verdict: never valid.

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
        vm.pauseTracing();
        vm.prank(WHALE);
        vm.resumeTracing();
        USDC.transfer(address(this), bal);
        assertGt(USDC.balanceOf(address(this)), 0);
    }
}
```
