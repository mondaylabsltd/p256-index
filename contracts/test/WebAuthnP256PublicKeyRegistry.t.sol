// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyRegistry} from "../src/WebAuthnP256PublicKeyRegistry.sol";
import {Base64Url} from "../src/Base64Url.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

contract WebAuthnP256PublicKeyRegistryTest is Test {
    WebAuthnP256PublicKeyRegistry public registry;

    // Fixed P-256 keypairs (generated offline; signatures are made at
    // runtime with vm.signP256 so every proof is real cryptography).
    uint256 constant PRIV1 = 0xbab26f1ab94e84a23199c46ec2dd4489507c278dd3ddf2ba0a47ec201205fe7a;
    bytes constant PUB1 =
        hex"041a8cc55e2d14a61c8f3f1bcf6f8e7e40fe09cc624a6b77f0539d5eebfafa7bc7880184f26b47cfc67b445168c34355416c93c73cb9b896b82be84486adf88ca0";
    uint256 constant PRIV2 = 0xd19d61c2c26eeff24e6f46686e83d2bcef1e14a161ce4bf7a1811d1df1c5caab;
    bytes constant PUB2 =
        hex"04f53cc0c730358ed61c9c73311fe16aa56ed1d719d3d025a956410d6e1ffb5b65073a0d501a779a3dcf0600d39e60f861498b791577de833af94bc2b44352dd3c";
    uint256 constant PRIV3 = 0xb6648b2469c90a65d2deda5ed97d4e1355b34d012d80ac2e3b6d0dbf322dd7bb;
    bytes constant PUB3 =
        hex"042ae594f6f136371270398d4d13b6311bed0ea7de72ee97199e94983b551d7be7774ba006a955cc5d6aa65f127d6086f162c5280382576e4851262d232bcf8c36";
    uint256 constant PRIV4 = 0x4ff0d0d44d98cbd19b2eee65e9ce24ac64908c3463c4335f68f5bdc954728cce;
    bytes constant PUB4 =
        hex"04a5252179f79a05821ddb772aa3758001279f824b82a47108d7f0b082dec6582ed50039489e8eab60a37136d9e94d33687255d261d96504e11020f8ba0a3324b1";
    uint256 constant PRIV5 = 0x8dc4bc66205dc7f28127831116bf49b7db232f7fbd613fa871732a8df39880db;
    bytes constant PUB5 =
        hex"0475e5c47cffda1da902a80270a07c305417d20ac28f7b02f0320d55677e7302b161a6518e70deed0f394efec311535a636be29e56d489f46bc969f2ca8882bf8a";
    uint256 constant PRIV6 = 0x950b13e206ce1aa33ad3bb736d45811028944ee37a234f4000de5c4d3ea631af;
    bytes constant PUB6 =
        hex"041a2633fe4f6da20c5eadf7da55ff584fa161c58f34cd66e8e2f3a47e810ecf1c90a9382cf4f406af31232b2067ca0c70673d8b4fd3d3bac3a5ccf9023e05c952";
    /// A second group key for multi-group scenarios.
    uint256 constant GPRIV2 = 0x97ed1498ce6e738fa927ab86be104b85e572330fda71a264c3650a73cf37d630;
    bytes constant GPUB2 =
        hex"04fc92700c4f14146b27098ded12688c9cdf46333a216149f97138245abd772395a2473f9813e5ff0aeb58321d740844ffc10155e68ef736e63a02e8713c3f0c5a";
    /// The default GROUP key of the test suite (a client-side software key
    /// in production; single-use).
    uint256 constant GPRIV = 0x7e7b5b9fba4858c30377ef6a0f3d3d9079cf00d2291bf0d468789a5cb5705aef;
    bytes constant GPUB =
        hex"049e666db13bc6d0a76ec6801fbe24864030f15eca3b2d07ebcaf824bb2dc4f0aea8221dc27980b7c133a00d910c39723eb1523e88ad050a7303bba8bde07367fa";

    // v1 || AAGUID || authData flags 0x5d || platform || usb|internal
    bytes constant ATTESTATION = hex"01fbfc3007154e4ecc8c0b6e020557d7bd5d0109";

    function setUp() public {
        // Stand in for the EIP-7951 / RIP-7212 precompile (live on Gnosis,
        // absent in the local EVM) with the audited Solidity fallback.
        vm.etch(address(0x100), address(new P256Verifier()).code);
        registry = new WebAuthnP256PublicKeyRegistry();
    }

    // ── Proof construction (real signatures) ───────────────────────────────

    function _authData(string memory rpId, bytes1 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(sha256(bytes(rpId)), flags, uint32(0));
    }

    function _proofOver(uint256 priv, bytes32 challenge, string memory rpId, bytes1 flags)
        internal
        pure
        returns (WebAuthnP256PublicKeyRegistry.Proof memory)
    {
        string memory clientData = string.concat(
            '{"type":"webauthn.get","challenge":"', Base64Url.encode32(challenge), '","origin":"https://example.com"}'
        );
        bytes memory authData = _authData(rpId, flags);
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));
        (bytes32 r, bytes32 s) = vm.signP256(priv, digest);
        return WebAuthnP256PublicKeyRegistry.Proof(authData, clientData, 23, 1, uint256(r), uint256(s));
    }

    function _emptyProof() internal pure returns (WebAuthnP256PublicKeyRegistry.Proof memory) {
        return WebAuthnP256PublicKeyRegistry.Proof("", "", 0, 0, 0, 0);
    }

    /// One member passkey signing at creation time: it binds only the
    /// group key and its own attestation — no metadata, no siblings.
    function _member(uint256 priv, bytes memory pubkey, bytes memory attestation, string memory rpId, bytes memory gpub)
        internal
        view
        returns (WebAuthnP256PublicKeyRegistry.Member memory)
    {
        bytes32 binding = registry.memberBindingFor(gpub, attestation);
        return WebAuthnP256PublicKeyRegistry.Member(
            pubkey, attestation, _proofOver(priv, registry.challengeFor(rpId, pubkey, binding), rpId, 0x05)
        );
    }

    /// The group key's silent closing signature over the frozen record.
    function _groupProof(
        uint256 gpriv,
        bytes memory gpub,
        string memory rpId,
        bytes memory metadata,
        WebAuthnP256PublicKeyRegistry.Member[] memory members
    ) internal view returns (WebAuthnP256PublicKeyRegistry.Proof memory) {
        bytes32 contentHash = registry.contentHashFor(rpId, metadata, gpub, members);
        return _proofOver(gpriv, registry.challengeFor(rpId, gpub, contentHash), rpId, 0x05);
    }

    /// Register a single-member group under the default test group key.
    function _register(uint256 priv, bytes memory pubkey, string memory rpId, bytes memory metadata) internal {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(priv, pubkey, "", rpId, GPUB);
        registry.register(rpId, metadata, GPUB, _groupProof(GPRIV, GPUB, rpId, metadata, members), members);
    }

    /// A referring passkey's payload: binds (group, attestation, reference
    /// metadata) — signable the moment the key exists.
    function _referrer(
        uint256 priv,
        bytes memory pubkey,
        bytes memory attestation,
        string memory rpId,
        bytes memory gpub,
        bytes memory metadata
    ) internal view returns (WebAuthnP256PublicKeyRegistry.Member memory) {
        bytes32 binding = registry.referenceBindingFor(gpub, attestation, metadata);
        return WebAuthnP256PublicKeyRegistry.Member(
            pubkey, attestation, _proofOver(priv, registry.challengeFor(rpId, pubkey, binding), rpId, 0x05)
        );
    }

    function _trio(string memory rpId) internal view returns (WebAuthnP256PublicKeyRegistry.Member[] memory members) {
        members = new WebAuthnP256PublicKeyRegistry.Member[](3);
        members[0] = _member(PRIV1, PUB1, "", rpId, GPUB);
        members[1] = _member(PRIV2, PUB2, "", rpId, GPUB);
        members[2] = _member(PRIV3, PUB3, "", rpId, GPUB);
    }

    // ── register: happy path ───────────────────────────────────────────────

    function test_register_storesAndIndexes() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, ATTESTATION, "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", hex"aa", members);

        vm.expectEmit(true, true, false, true);
        emit WebAuthnP256PublicKeyRegistry.EntryCreated(0, keccak256(PUB1), PUB1, ATTESTATION);
        vm.expectEmit(true, true, true, true);
        emit WebAuthnP256PublicKeyRegistry.MemberJoined(0, 0, keccak256(PUB1));
        vm.expectEmit(true, true, true, true);
        emit WebAuthnP256PublicKeyRegistry.GroupCreated(0, keccak256(bytes("rp1")), keccak256(GPUB), GPUB, 1);
        registry.register("rp1", hex"aa", GPUB, gp, members);

        assertEq(registry.getTotalEntries(), 1);
        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalReferences(), 0);

        WebAuthnP256PublicKeyRegistry.Entry memory entry = registry.getEntry(0);
        assertEq(entry.publicKey, PUB1);
        assertEq(entry.attestation, ATTESTATION);
        assertTrue(registry.hasEntry(PUB1));
        (bool exists, uint256 entryId,) = registry.getEntryByKey(PUB1);
        assertTrue(exists);
        assertEq(entryId, 0);

        WebAuthnP256PublicKeyRegistry.Unit memory unit = registry.getUnit(0);
        assertEq(unit.rpId, "rp1");
        assertEq(unit.metadata, hex"aa");
        assertEq(unit.groupPublicKey, GPUB);
        assertEq(unit.memberCount, 1);
        assertEq(unit.contentHash, registry.contentHashFor("rp1", hex"aa", GPUB, members));

        assertTrue(registry.isMember(GPUB, PUB1));
        assertEq(registry.getTotalGroupMembers(0), 1);
        assertEq(registry.getTotalGroupsOfKey(PUB1), 1);
    }

    function test_getUnitByGroupKey_andContentHash() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");
        (bool exists, uint256 unitId, WebAuthnP256PublicKeyRegistry.Unit memory unit) =
            registry.getUnitByGroupKey(GPUB);
        assertTrue(exists);
        assertEq(unitId, 0);
        assertEq(unit.metadata, hex"aa");
        (bool hasContent, uint256 byContent) = registry.getUnitIdByContentHash(unit.contentHash);
        assertTrue(hasContent);
        assertEq(byContent, 0);
        assertTrue(registry.isContentRegistered(unit.contentHash));

        (exists,,) = registry.getUnitByGroupKey(GPUB2);
        assertFalse(exists);
    }

    // ── Entries are global: one key, one row, forever ──────────────────────

    function test_entryIsGlobal_acrossGroups() public {
        _register(PRIV1, PUB1, "rp1", hex"aa"); // group 0 under GPUB: [PUB1]

        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](2);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB2);
        members[1] = _member(PRIV2, PUB2, "", "rp1", GPUB2);
        registry.register("rp1", hex"bb", GPUB2, _groupProof(GPRIV2, GPUB2, "rp1", hex"bb", members), members);

        // PUB1 reused: still ONE entry; PUB2 new: second entry.
        assertEq(registry.getTotalEntries(), 2);
        assertEq(registry.getTotalUnits(), 2);
        assertEq(registry.getTotalGroupsOfKey(PUB1), 2);
        (uint256 total, uint256[] memory unitIds) = registry.getGroupsOfKey(PUB1, 0, 10, false);
        assertEq(total, 2);
        assertEq(unitIds[0], 0);
        assertEq(unitIds[1], 1);
        assertTrue(registry.isMember(GPUB, PUB1));
        assertTrue(registry.isMember(GPUB2, PUB1));
        assertFalse(registry.isMember(GPUB, PUB2));
    }

    function test_entryAttestation_isFixedForever() public {
        _register(PRIV1, PUB1, "rp1", hex"aa"); // PUB1's file: attestation ""

        // Rejoining another group with a DIFFERENT attestation claim fails.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, ATTESTATION, "rp1", GPUB2);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV2, GPUB2, "rp1", hex"bb", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.AttestationMismatch.selector, 0));
        registry.register("rp1", hex"bb", GPUB2, gp, members);
    }

    // ── Groups are frozen and group keys single-use ────────────────────────

    function test_groupKeyIsSingleUse() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV2, PUB2, "", "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", hex"bb", members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.GroupKeyAlreadyUsed.selector, keccak256(GPUB))
        );
        registry.register("rp1", hex"bb", GPUB, gp, members);
    }

    function test_frontRun_cannotAlterAnything() public {
        // The mempool attack surface: the group proof binds the whole
        // frozen record, every member binds (group, own attestation).
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", hex"1234", members);

        // Swap the metadata → group signature dies.
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"9999", GPUB, gp, members);

        // Drop a member → group signature dies.
        WebAuthnP256PublicKeyRegistry.Member[] memory subset = new WebAuthnP256PublicKeyRegistry.Member[](2);
        (subset[0], subset[1]) = (members[0], members[1]);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"1234", GPUB, gp, subset);

        // The untampered original lands.
        registry.register("rp1", hex"1234", GPUB, gp, members);
        assertEq(registry.getTotalGroupMembers(0), 3);
    }

    function test_memberProof_cannotBeRePairedWithAnotherGroup() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB); // bound to GPUB
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV2, GPUB2, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB2, gp, members);
    }

    function test_wrongKeySignature_reverts() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 binding = registry.memberBindingFor(GPUB, "");
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", _proofOver(PRIV2, registry.challengeFor("rp1", PUB1, binding), "rp1", 0x05)
        );
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_rpIdIsBound_throughChallengeAndAuthData() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.RpIdMismatch.selector);
        registry.register("rp2", "", GPUB, gp, members);
    }

    function test_userPresentFlagRequired() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 binding = registry.memberBindingFor(GPUB, "");
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", _proofOver(PRIV1, registry.challengeFor("rp1", PUB1, binding), "rp1", 0x04)
        );
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_wrongCeremonyType_reverts() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 challenge = registry.challengeFor("rp1", PUB1, registry.memberBindingFor(GPUB, ""));
        string memory clientData =
            string.concat('{"type":"webauthn.create","challenge":"', Base64Url.encode32(challenge), '"}');
        bytes memory authData = _authData("rp1", 0x05);
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));
        (bytes32 r, bytes32 s) = vm.signP256(PRIV1, digest);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", WebAuthnP256PublicKeyRegistry.Proof(authData, clientData, 26, 1, uint256(r), uint256(s))
        );
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_challengeIndexBeyondClientData_reverts() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        members[0].proof.challengeIndex = 10_000; // far past the JSON's end
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    // ── register: batch and shape validation ───────────────────────────────

    function test_multiMember_oneBadProofRevertsAll() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        members[2].proof = members[1].proof; // member 3 carries member 2's signature
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", hex"1234", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"1234", GPUB, gp, members);
        assertEq(registry.getTotalEntries(), 0);
        assertEq(registry.getTotalUnits(), 0);
        assertFalse(registry.hasEntry(PUB1));
        // Nothing consumed (state reverted): correct proofs retry fine.
        WebAuthnP256PublicKeyRegistry.Member[] memory fixedMembers = _trio("rp1");
        registry.register(
            "rp1", hex"1234", GPUB, _groupProof(GPRIV, GPUB, "rp1", hex"1234", fixedMembers), fixedMembers
        );
        assertTrue(registry.hasEntry(PUB1));
    }

    function test_memberCountBounds() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory none = new WebAuthnP256PublicKeyRegistry.Member[](0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidMemberCount.selector, 0));
        registry.register("rp1", "", GPUB, _emptyProof(), none);

        WebAuthnP256PublicKeyRegistry.Member[] memory eight = new WebAuthnP256PublicKeyRegistry.Member[](8);
        for (uint256 i = 0; i < 8; i++) {
            eight[i] = WebAuthnP256PublicKeyRegistry.Member(PUB1, "", _emptyProof());
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidMemberCount.selector, 8));
        registry.register("rp1", "", GPUB, _emptyProof(), eight);
    }

    function test_sevenMembersFit() public {
        uint256[6] memory privs = [PRIV1, PRIV2, PRIV3, PRIV4, PRIV5, PRIV6];
        bytes[6] memory pubs = [PUB1, PUB2, PUB3, PUB4, PUB5, PUB6];
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](7);
        for (uint256 i = 0; i < 6; i++) {
            members[i] = _member(privs[i], pubs[i], "", "rp1", GPUB);
        }
        members[6] = _member(GPRIV2, GPUB2, "", "rp1", GPUB); // 7th distinct key
        registry.register("rp1", hex"beef", GPUB, _groupProof(GPRIV, GPUB, "rp1", hex"beef", members), members);
        assertEq(registry.getTotalEntries(), 7);
        assertEq(registry.getTotalGroupMembers(0), 7);
    }

    function test_duplicateMemberKeyRejected() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](2);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        members[1] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.DuplicateMemberKey.selector, 1));
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_groupKeyCannotAlsoBeAMember() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(GPRIV, GPUB, "", "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.DuplicateMemberKey.selector, 0));
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_validationBounds() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);

        vm.expectRevert(WebAuthnP256PublicKeyRegistry.EmptyRpId.selector);
        registry.register("", "", GPUB, _emptyProof(), members);

        string memory longRp = string(new bytes(254));
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.RpIdTooLong.selector, 254));
        registry.register(longRp, "", GPUB, _emptyProof(), members);

        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.MetadataTooLong.selector, 2049));
        registry.register("rp1", new bytes(2049), GPUB, _emptyProof(), members);
    }

    function test_metadataAtCapRegisters() public {
        _register(PRIV1, PUB1, "rp1", new bytes(2048));
        assertEq(registry.getUnit(0).metadata.length, 2048);
    }

    function test_attestationShape() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB1, new bytes(19), _emptyProof());
        WebAuthnP256PublicKeyRegistry.Proof memory gp1 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 19));
        registry.register("rp1", "", GPUB, gp1, members);

        bytes memory wrongVersion = ATTESTATION;
        wrongVersion[0] = 0x02;
        members[0].attestation = wrongVersion;
        WebAuthnP256PublicKeyRegistry.Proof memory gp2 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 20));
        registry.register("rp1", "", GPUB, gp2, members);
    }

    function test_publicKeyShape() public {
        WebAuthnP256PublicKeyRegistry.Proof memory dummy = _emptyProof();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);

        members[0] = WebAuthnP256PublicKeyRegistry.Member(hex"0400", "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp1 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyLength.selector, 2));
        registry.register("rp1", "", GPUB, gp1, members);

        bytes memory badPrefix = PUB1;
        badPrefix[0] = 0x02;
        members[0] = WebAuthnP256PublicKeyRegistry.Member(badPrefix, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp2 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPrefix.selector, bytes1(0x02))
        );
        registry.register("rp1", "", GPUB, gp2, members);

        bytes memory offCurve = bytes.concat(hex"04", bytes32(uint256(1)), bytes32(uint256(1)));
        members[0] = WebAuthnP256PublicKeyRegistry.Member(offCurve, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp3 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPoint.selector);
        registry.register("rp1", "", GPUB, gp3, members);

        bytes memory outOfField = bytes.concat(hex"04", bytes32(type(uint256).max), bytes32(uint256(1)));
        members[0] = WebAuthnP256PublicKeyRegistry.Member(outOfField, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp4 = _groupProof(GPRIV, GPUB, "rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyCoordinate.selector);
        registry.register("rp1", "", GPUB, gp4, members);

        // The group key gets the same shape validation.
        WebAuthnP256PublicKeyRegistry.Member[] memory ok = new WebAuthnP256PublicKeyRegistry.Member[](1);
        ok[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyLength.selector, 2));
        registry.register("rp1", "", hex"0400", _emptyProof(), ok);
    }

    // ── refer: a passkey pointing at an existing group ─────────────────────

    function test_refer_storesInItsOwnTable() public {
        _register(PRIV1, PUB1, "rp1", hex"aa"); // group 0

        WebAuthnP256PublicKeyRegistry.Member memory referrer =
            _referrer(PRIV2, PUB2, ATTESTATION, "rp1", GPUB, hex"cafe");
        vm.expectEmit(true, true, true, true);
        emit WebAuthnP256PublicKeyRegistry.ReferenceCreated(0, 1, 0, keccak256(PUB2), keccak256(GPUB));
        registry.refer(GPUB, hex"cafe", referrer);

        // Its own table and counters...
        assertEq(registry.getTotalReferences(), 1);
        WebAuthnP256PublicKeyRegistry.Reference memory stored = registry.getReference(0);
        assertEq(stored.entryId, 1);
        assertEq(stored.unitId, 0);
        assertEq(stored.metadata, hex"cafe");
        assertTrue(registry.isReferenced(GPUB, PUB2));
        assertEq(registry.getTotalReferencesOfKey(PUB2), 1);
        assertEq(registry.getTotalReferencesToGroup(GPUB), 1);
        (uint256 total, uint256[] memory ids) = registry.getReferencesOfKey(PUB2, 0, 10, false);
        assertEq(total, 1);
        assertEq(ids[0], 0);

        // ...the referrer got its global file...
        assertEq(registry.getTotalEntries(), 2);
        assertTrue(registry.hasEntry(PUB2));

        // ...and the group is COMPLETELY untouched: not a member, group
        // record and stats identical.
        assertFalse(registry.isMember(GPUB, PUB2));
        assertEq(registry.getTotalGroupMembers(0), 1);
        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalGroupsOfKey(PUB2), 0);
    }

    function test_refer_requiresAnExistingGroup() public {
        WebAuthnP256PublicKeyRegistry.Member memory referrer = _referrer(PRIV2, PUB2, "", "rp1", GPUB, "");
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.GroupNotFound.selector, keccak256(GPUB)));
        registry.refer(GPUB, "", referrer);
    }

    function test_refer_oncePerGroupAndKey() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");
        registry.refer(GPUB, "", _referrer(PRIV2, PUB2, "", "rp1", GPUB, ""));

        WebAuthnP256PublicKeyRegistry.Member memory again = _referrer(PRIV2, PUB2, "", "rp1", GPUB, hex"01");
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.AlreadyReferenced.selector, 0));
        registry.refer(GPUB, hex"01", again);
    }

    function test_refer_bindsGroupAttestationAndMetadata() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");

        // Swap the reference metadata after signing → dead.
        WebAuthnP256PublicKeyRegistry.Member memory referrer = _referrer(PRIV2, PUB2, "", "rp1", GPUB, hex"cafe");
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.refer(GPUB, hex"beef", referrer);

        // A reference signed for group A cannot be pointed at group B.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV3, PUB3, "", "rp1", GPUB2);
        registry.register("rp1", hex"bb", GPUB2, _groupProof(GPRIV2, GPUB2, "rp1", hex"bb", members), members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.refer(GPUB2, hex"cafe", referrer);
    }

    function test_refer_memberProofIsNotAReferenceProof() public {
        // A membership proof (member binding) cannot be replayed as a
        // reference: the bindings differ.
        _register(PRIV1, PUB1, "rp1", hex"aa");
        WebAuthnP256PublicKeyRegistry.Member memory asMember = _member(PRIV2, PUB2, "", "rp1", GPUB);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.refer(GPUB, "", asMember);
    }

    function test_refer_existingEntryKeepsItsFile() public {
        // A key that is already a member elsewhere refers with its FIXED
        // attestation; a mismatching claim is refused.
        _register(PRIV1, PUB1, "rp1", hex"aa"); // PUB1 file: attestation ""
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV2, PUB2, "", "rp1", GPUB2);
        registry.register("rp1", hex"bb", GPUB2, _groupProof(GPRIV2, GPUB2, "rp1", hex"bb", members), members);

        registry.refer(GPUB2, "", _referrer(PRIV1, PUB1, "", "rp1", GPUB2, ""));
        assertEq(registry.getTotalEntries(), 2); // no third entry
        assertTrue(registry.isReferenced(GPUB2, PUB1));

        WebAuthnP256PublicKeyRegistry.Member memory lying = _referrer(PRIV1, PUB1, ATTESTATION, "rp1", GPUB, "");
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.AttestationMismatch.selector, 0));
        registry.refer(GPUB, "", lying);
    }

    // ── Cross-language pinned vectors and binding negatives ────────────────

    /// Pinned with cast (an implementation independent of both this test
    /// and the Rust mirror): any encoding drift on either side of the
    /// Rust/Solidity boundary breaks these constants. The same constants
    /// are asserted in p256-registrar/src/protocol.rs.
    function test_pinnedVectors_matchIndependentEncoding() public view {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB1, "", _emptyProof());

        assertEq(
            registry.memberBindingFor(GPUB, ""),
            bytes32(0x75a5d4ac7bfd9ba67dd55f90f5063062d6899090a46608ac1b10e9a51e359bc6)
        );
        assertEq(
            registry.referenceBindingFor(GPUB, "", hex"aa"),
            bytes32(0xd5213d11b1f268a3098df33fa192e334e92788516ca70f286167a1e89457c2a3)
        );
        bytes32 contentHash = registry.contentHashFor("example.com", hex"aa", GPUB, members);
        assertEq(contentHash, bytes32(0x1d7f01eb5c0170f9196956c4d7b56484cc335ba23757431f60fb4aeb626f78eb));
        // The challenge formula, pinned with chainid 100 and a fixed
        // registry address (the deployed function substitutes its own).
        assertEq(
            keccak256(
                abi.encode(
                    uint256(100), address(0x1111111111111111111111111111111111111111), "example.com", PUB1, contentHash
                )
            ),
            bytes32(0xd17270edef23ad83ebbf91a0d4f50caf64ef9b64bb85bec51192e36f311082ce)
        );
        // And the deployed function is exactly that formula over its own
        // identity.
        assertEq(
            registry.challengeFor("example.com", PUB1, contentHash),
            keccak256(abi.encode(block.chainid, address(registry), "example.com", PUB1, contentHash))
        );
    }

    function test_challengeBindsRegistryInstance() public {
        WebAuthnP256PublicKeyRegistry other = new WebAuthnP256PublicKeyRegistry();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB); // signed for `registry`
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);

        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        other.register("rp1", "", GPUB, gp, members);

        registry.register("rp1", "", GPUB, gp, members); // home instance still fine
        assertEq(registry.getTotalUnits(), 1);
    }

    function test_challengeBindsChainId() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1", GPUB);
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof(GPRIV, GPUB, "rp1", "", members);

        vm.chainId(31338); // a fork with a different chain id rejects them
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    // ── Reads, pagination, enumeration ─────────────────────────────────────

    function test_groupMembers_paginate() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        registry.register("rp1", hex"1234", GPUB, _groupProof(GPRIV, GPUB, "rp1", hex"1234", members), members);

        (uint256 total, uint256[] memory entryIds, WebAuthnP256PublicKeyRegistry.Entry[] memory entries) =
            registry.getGroupMembers(0, 1, 1, false);
        assertEq(total, 3);
        assertEq(entryIds.length, 1);
        assertEq(entryIds[0], 1);
        assertEq(entries[0].publicKey, PUB2);

        (, entryIds,) = registry.getGroupMembers(0, 0, 10, true);
        assertEq(entryIds[0], 2);

        (total, entryIds,) = registry.getGroupMembers(0, 9, 10, false);
        assertEq(total, 3);
        assertEq(entryIds.length, 0);
    }

    function test_rpIdEnumeration_countsGroups() public {
        _register(PRIV1, PUB1, "rp1", hex"01");
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV2, PUB2, "", "rp2", GPUB2);
        registry.register("rp2", hex"02", GPUB2, _groupProof(GPRIV2, GPUB2, "rp2", hex"02", members), members);

        assertEq(registry.getTotalRpIds(), 2);
        assertEq(registry.getTotalGroupsByRpId("rp1"), 1);
        assertEq(registry.getTotalGroupsByRpId("rp2"), 1);
        (uint256 total, string[] memory rpIds, uint256[] memory counts,) = registry.getRpIds(0, 10, false);
        assertEq(total, 2);
        assertEq(rpIds[0], "rp1");
        assertEq(counts[0], 1);
        (uint256 groupTotal, uint256[] memory unitIds) = registry.getGroupsByRpId("rp2", 0, 10, false);
        assertEq(groupTotal, 1);
        assertEq(unitIds[0], 1);

        // Past-the-end page: totals stay, slices are empty.
        (total, rpIds, counts,) = registry.getRpIds(5, 10, false);
        assertEq(total, 2);
        assertEq(rpIds.length, 0);
    }

    function test_outOfRangeReads_revert() public {
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.EntryNotFound.selector, 0));
        registry.getEntry(0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitNotFound.selector, 0));
        registry.getUnit(0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.ReferenceNotFound.selector, 0));
        registry.getReference(0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitNotFound.selector, 0));
        registry.getGroupMembers(0, 0, 10, false);
    }

    function test_keyRolesAreSeparateNamespaces() public {
        // Pinned semantics: roles are distinct only within one call. A
        // used group key may later join another group as a member (gaining
        // an entry), and an entry-holding key may open a group as its
        // group key. Structural counters stay exact.
        _register(PRIV1, PUB1, "rp1", hex"01"); // GPUB used as a group key

        // GPUB the ex-group-key joins GPUB2's group as a regular member.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(GPRIV, GPUB, "", "rp1", GPUB2);
        registry.register("rp1", hex"02", GPUB2, _groupProof(GPRIV2, GPUB2, "rp1", hex"02", members), members);
        assertTrue(registry.hasEntry(GPUB));
        assertTrue(registry.isMember(GPUB2, GPUB));

        // PUB1, an entry-holding member, opens a brand-new group as its
        // group key.
        WebAuthnP256PublicKeyRegistry.Member[] memory third = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 binding = registry.memberBindingFor(PUB1, "");
        third[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB2, "", _proofOver(PRIV2, registry.challengeFor("rp1", PUB2, binding), "rp1", 0x05)
        );
        bytes32 contentHash = registry.contentHashFor("rp1", hex"03", PUB1, third);
        WebAuthnP256PublicKeyRegistry.Proof memory closer =
            _proofOver(PRIV1, registry.challengeFor("rp1", PUB1, contentHash), "rp1", 0x05);
        registry.register("rp1", hex"03", PUB1, closer, third);

        assertEq(registry.getTotalUnits(), 3); // GPUB, GPUB2, PUB1 groups
        assertEq(registry.getTotalEntries(), 3); // PUB1, GPUB, PUB2 files
        (bool exists,,) = registry.getUnitByGroupKey(PUB1);
        assertTrue(exists);
    }

    function test_ids_areSequentialAndImmutable() public {
        _register(PRIV1, PUB1, "rp1", hex"01"); // unit 0, entry 0
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](2);
        members[0] = _member(PRIV2, PUB2, "", "rp2", GPUB2);
        members[1] = _member(PRIV3, PUB3, "", "rp2", GPUB2);
        registry.register("rp2", hex"02", GPUB2, _groupProof(GPRIV2, GPUB2, "rp2", hex"02", members), members);
        registry.refer(GPUB, "", _referrer(PRIV2, PUB2, "", "rp1", GPUB, "")); // reference 0

        WebAuthnP256PublicKeyRegistry.Entry memory before = registry.getEntry(0);
        // More writes, under a third fresh group key (they are single-use).
        WebAuthnP256PublicKeyRegistry.Member[] memory third = new WebAuthnP256PublicKeyRegistry.Member[](1);
        third[0] = _member(PRIV4, PUB4, "", "rp3", PUB5);
        registry.register("rp3", hex"03", PUB5, _groupProof(PRIV5, PUB5, "rp3", hex"03", third), third);
        WebAuthnP256PublicKeyRegistry.Entry memory later = registry.getEntry(0);
        assertEq(later.publicKey, before.publicKey);
        assertEq(registry.getTotalEntries(), 4);
        assertEq(registry.getTotalUnits(), 3);
        assertEq(registry.getTotalReferences(), 1);
        assertEq(registry.getReference(0).entryId, 1);
    }
}
