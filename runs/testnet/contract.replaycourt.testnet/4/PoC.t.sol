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
