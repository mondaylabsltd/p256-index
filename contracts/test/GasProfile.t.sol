// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyRegistry} from "../src/WebAuthnP256PublicKeyRegistry.sol";
import {Base64Url} from "../src/Base64Url.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

/// Gas profile for register(). NOTE: the local stand-in verifier costs
/// ~330k gas per proof; on chains with the real EIP-7951 precompile
/// (e.g. Gnosis) each verification is ~3.4k gas instead — subtract
/// ~330k per member from these numbers for the on-chain estimate.
/// Run with: forge test --match-contract GasProfileTest -vv
contract GasProfileTest is Test {
    WebAuthnP256PublicKeyRegistry public registry;

    uint256 constant PRIV1 = 0xbab26f1ab94e84a23199c46ec2dd4489507c278dd3ddf2ba0a47ec201205fe7a;
    bytes constant PUB1 =
        hex"041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0";

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        registry = new WebAuthnP256PublicKeyRegistry();
    }

    function _proofOver(bytes32 challenge) internal pure returns (WebAuthnP256PublicKeyRegistry.Proof memory) {
        string memory clientData = string.concat(
            '{"type":"webauthn.get","challenge":"', Base64Url.encode32(challenge), '","origin":"https://example.com"}'
        );
        bytes memory authData = abi.encodePacked(sha256(bytes("rp.example.com")), bytes1(0x05), uint32(0));
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));
        (bytes32 r, bytes32 s) = vm.signP256(PRIV1, digest);
        return WebAuthnP256PublicKeyRegistry.Proof(authData, clientData, 23, 1, uint256(r), uint256(s));
    }

    function test_gasProfile_register() public {
        uint256[4] memory sizes = [uint256(1), 3, 5, 7];
        for (uint256 i = 0; i < sizes.length; i++) {
            uint256 n = sizes[i];
            // Distinct metadata per unit so content dedup never trips;
            // Vela-sized payload (~487B for a 7-key derivation preimage).
            bytes memory metadata = abi.encodePacked(uint256(i), new bytes(480));
            bytes32 nonce = keccak256(abi.encode("gas-nonce", i));
            bytes32 challenge = registry.challengeFor("rp.example.com", PUB1, nonce);
            WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](n);
            for (uint256 m = 0; m < n; m++) {
                members[m] = WebAuthnP256PublicKeyRegistry.Member(PUB1, "", _proofOver(challenge));
            }
            bytes memory callData =
                abi.encodeCall(WebAuthnP256PublicKeyRegistry.register, ("rp.example.com", metadata, nonce, members));
            uint256 before = gasleft();
            registry.register("rp.example.com", metadata, nonce, members);
            uint256 execGas = before - gasleft();
            console2.log("members:", n);
            console2.log("  exec gas (mock verifier):", execGas);
            console2.log("  approx full tx gas:", 21_000 + callData.length * 16 + execGas);
        }
    }
}
