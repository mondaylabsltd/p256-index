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

    // Same fixed keypairs as the main suite: member keys must be distinct
    // within a unit, so each size draws from this pool.
    uint256[7] PRIVS = [
        0xbab26f1ab94e84a23199c46ec2dd4489507c278dd3ddf2ba0a47ec201205fe7a,
        0xd19d61c2c26eeff24e6f46686e83d2bcef1e14a161ce4bf7a1811d1df1c5caab,
        0xb6648b2469c90a65d2deda5ed97d4e1355b34d012d80ac2e3b6d0dbf322dd7bb,
        0x4ff0d0d44d98cbd19b2eee65e9ce24ac64908c3463c4335f68f5bdc954728cce,
        0x8dc4bc66205dc7f28127831116bf49b7db232f7fbd613fa871732a8df39880db,
        0x950b13e206ce1aa33ad3bb736d45811028944ee37a234f4000de5c4d3ea631af,
        0x97ed1498ce6e738fa927ab86be104b85e572330fda71a264c3650a73cf37d630
    ];
    bytes[7] PUBS = [
        bytes(
            hex"041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0"
        ),
        bytes(
            hex"04f53cc0c730358ed61c9c73311fe16aa56ed1d719d3d025a956410d6e1ffb5b65073a0d501a779a3dcf0600d39e60f861498b791577de833af94bc2b44352dd3c"
        ),
        bytes(
            hex"042ae594f6f136371270398d4d13b6311bed0ea7de72ee97199e94983b551d7be7774ba006a955cc5d6aa65f127d6086f162c5280382576e4851262d232bcf8c36"
        ),
        bytes(
            hex"04a5252179f79a05821ddb772aa3758001279f824b82a47108d7f0b082dec6582ed50039489e8eab60a37136d9e94d33687255d261d96504e11020f8ba0a3324b1"
        ),
        bytes(
            hex"0475e5c47cffda1da902a80270a07c305417d20ac28f7b02f0320d55677e7302b161a6518e70deed0f394efec311535a636be29e56d489f46bc969f2ca8882bf8a"
        ),
        bytes(
            hex"041a2633fe4f6da20c5eadf7da55ff584fa161c58f34cd66e8e2f3a47e810ecf1c90a9382cf4f406af31232b2067ca0c70673d8b4fd3d3bac3a5ccf9023e05c952"
        ),
        bytes(
            hex"04fc92700c4f14146b27098ded12688c9cdf46333a216149f97138245abd772395a2473f9813e5ff0aeb58321d740844ffc10155e68ef736e63a02e8713c3f0c5a"
        )
    ];

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        registry = new WebAuthnP256PublicKeyRegistry();
    }

    function _proofOver(uint256 priv, bytes32 challenge)
        internal
        pure
        returns (WebAuthnP256PublicKeyRegistry.Proof memory)
    {
        string memory clientData = string.concat(
            '{"type":"webauthn.get","challenge":"', Base64Url.encode32(challenge), '","origin":"https://example.com"}'
        );
        bytes memory authData = abi.encodePacked(sha256(bytes("rp.example.com")), bytes1(0x05), uint32(0));
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));
        (bytes32 r, bytes32 s) = vm.signP256(priv, digest);
        return WebAuthnP256PublicKeyRegistry.Proof(authData, clientData, 23, 1, uint256(r), uint256(s));
    }

    uint256 constant GPRIV = 0x7e7b5b9fba4858c30377ef6a0f3d3d9079cf00d2291bf0d468789a5cb5705aef;
    bytes constant GPUB =
        hex"049e666db13bc6d0a76ec6801fbe24864030f15eca3b2d07ebcaf824bb2dc4f0aea8221dc27980b7c133a00d910c39723eb1523e88ad050a7303bba8bde07367fa";

    function test_gasProfile_register() public {
        uint256[4] memory sizes = [uint256(1), 3, 5, 7];
        // Group keys are single-use: one fresh group per size (a key used
        // as a group elsewhere may still be a member here).
        uint256[4] memory gprivs = [PRIVS[4], PRIVS[5], PRIVS[6], GPRIV];
        for (uint256 i = 0; i < sizes.length; i++) {
            uint256 n = sizes[i];
            bytes memory gpub = i == 3 ? GPUB : PUBS[4 + i];
            // Distinct metadata per unit; Vela-sized payload (~487B).
            bytes memory metadata = abi.encodePacked(uint256(i), new bytes(480));
            WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](n);
            for (uint256 m = 0; m < n; m++) {
                bytes32 binding = registry.memberBindingFor(gpub, "");
                members[m] = WebAuthnP256PublicKeyRegistry.Member(
                    PUBS[m], "", "", "", "", _proofOver(PRIVS[m], registry.challengeFor("rp.example.com", PUBS[m], binding))
                );
            }
            bytes32 contentHash = registry.contentHashFor("rp.example.com", metadata, gpub, members);
            WebAuthnP256PublicKeyRegistry.Proof memory groupProof =
                _proofOver(gprivs[i], registry.challengeFor("rp.example.com", gpub, contentHash));
            bytes memory callData = abi.encodeCall(
                WebAuthnP256PublicKeyRegistry.register, ("rp.example.com", metadata, gpub, groupProof, members)
            );
            uint256 before = gasleft();
            registry.register("rp.example.com", metadata, gpub, groupProof, members);
            uint256 execGas = before - gasleft();
            console2.log("members:", n);
            console2.log("  exec gas (mock verifier):", execGas);
            console2.log("  approx full tx gas:", 21_000 + callData.length * 16 + execGas);
        }

        // One reference on top of the last group.
        WebAuthnP256PublicKeyRegistry.Member memory referrer;
        {
            bytes32 binding = registry.referenceBindingFor(GPUB, "", hex"cafe");
            referrer = WebAuthnP256PublicKeyRegistry.Member(
                PUBS[0], "", "", "", "", _proofOver(PRIVS[0], registry.challengeFor("rp.example.com", PUBS[0], binding))
            );
        }
        uint256 beforeRefer = gasleft();
        registry.refer(GPUB, hex"cafe", referrer);
        console2.log("refer exec gas (mock verifier):", beforeRefer - gasleft());
    }
}
