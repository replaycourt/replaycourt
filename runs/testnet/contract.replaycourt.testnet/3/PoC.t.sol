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
