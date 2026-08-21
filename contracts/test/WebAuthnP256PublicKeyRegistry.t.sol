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
    uint256 constant PRIV7 = 0x97ed1498ce6e738fa927ab86be104b85e572330fda71a264c3650a73cf37d630;
    bytes constant PUB7 =
        hex"04fc92700c4f14146b27098ded12688c9cdf46333a216149f97138245abd772395a2473f9813e5ff0aeb58321d740844ffc10155e68ef736e63a02e8713c3f0c5a";
    /// The default GROUP key of the test suite (a client-side software key
    /// in production; never a passkey).
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

    /// One member passkey signing at creation time: it binds only the group
    /// key and its own attestation — no metadata, no siblings.
    function _member(uint256 priv, bytes memory pubkey, bytes memory attestation, string memory rpId)
        internal
        view
        returns (WebAuthnP256PublicKeyRegistry.Member memory)
    {
        bytes32 binding = registry.memberBindingFor(GPUB, attestation);
        return WebAuthnP256PublicKeyRegistry.Member(
            pubkey, attestation, _proofOver(priv, registry.challengeFor(rpId, pubkey, binding), rpId, 0x05)
        );
    }

    /// The group key's silent closing signature over the finished unit.
    function _groupProof(string memory rpId, bytes memory metadata, WebAuthnP256PublicKeyRegistry.Member[] memory members)
        internal
        view
        returns (WebAuthnP256PublicKeyRegistry.Proof memory)
    {
        bytes32 contentHash = registry.contentHashFor(rpId, metadata, GPUB, members);
        return _proofOver(GPRIV, registry.challengeFor(rpId, GPUB, contentHash), rpId, 0x05);
    }

    function _register(uint256 priv, bytes memory pubkey, string memory rpId, bytes memory metadata) internal {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(priv, pubkey, "", rpId);
        registry.register(rpId, metadata, GPUB, _groupProof(rpId, metadata, members), members);
    }

    function _trio(string memory rpId) internal view returns (WebAuthnP256PublicKeyRegistry.Member[] memory members) {
        members = new WebAuthnP256PublicKeyRegistry.Member[](3);
        members[0] = _member(PRIV1, PUB1, "", rpId);
        members[1] = _member(PRIV2, PUB2, "", rpId);
        members[2] = _member(PRIV3, PUB3, "", rpId);
    }

    // ── Happy path ─────────────────────────────────────────────────────────

    function test_register_storesAndIndexes() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, ATTESTATION, "rp1");

        vm.expectEmit(true, true, true, true);
        emit WebAuthnP256PublicKeyRegistry.UnitRegistered(0, keccak256(bytes("rp1")), keccak256(GPUB), 0, 1, GPUB);
        registry.register("rp1", hex"aa", GPUB, _groupProof("rp1", hex"aa", members), members);

        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalEntries(), 1);
        WebAuthnP256PublicKeyRegistry.EntryView memory entry = registry.getEntry(0);
        assertEq(entry.publicKey, PUB1);
        assertEq(entry.rpId, "rp1");
        assertEq(entry.metadata, hex"aa");
        assertEq(entry.attestation, ATTESTATION);
        assertEq(entry.groupPublicKey, GPUB);
        assertEq(entry.unitId, 0);
        assertEq(entry.memberCount, 1);
        assertTrue(registry.hasEntries(PUB1));
        assertEq(registry.getTotalUnitsByGroupKey(GPUB), 1);
        assertTrue(registry.isContentRegistered(registry.contentHashFor("rp1", hex"aa", GPUB, members)));
    }

    function test_contentHashIsTheStableUnitIdentity() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        bytes32 contentHash = registry.contentHashFor("rp1", hex"aa", GPUB, members);

        (bool exists, uint256 unitId) = registry.getUnitIdByContentHash(contentHash);
        assertFalse(exists);

        registry.register("rp1", hex"aa", GPUB, _groupProof("rp1", hex"aa", members), members);
        (exists, unitId) = registry.getUnitIdByContentHash(contentHash);
        assertTrue(exists);
        assertEq(unitId, 0);
    }

    function test_sameKey_multipleUnits_inOrder() public {
        _register(PRIV1, PUB1, "rp1", hex"0a");
        _register(PRIV1, PUB1, "rp1", hex"0b");
        (uint256 total, WebAuthnP256PublicKeyRegistry.EntryView[] memory records) =
            registry.getEntriesByKey(PUB1, 0, 10, false);
        assertEq(total, 2);
        assertEq(records[0].metadata, hex"0a");
        assertEq(records[1].metadata, hex"0b");
        assertEq(records[1].unitId, 1);
        // Both units index under the shared test group key.
        assertEq(registry.getTotalUnitsByGroupKey(GPUB), 2);
    }

    function test_unregisteredKey_hasNothing() public {
        _register(PRIV1, PUB1, "rp1", "");
        assertFalse(registry.hasEntries(PUB2));
        (uint256 total,) = registry.getEntriesByKey(PUB2, 0, 10, false);
        assertEq(total, 0);
    }

    function test_groupKeyIndexing_paginates() public {
        _register(PRIV1, PUB1, "rp1", hex"01");
        _register(PRIV2, PUB2, "rp1", hex"02");
        _register(PRIV3, PUB3, "rp2", hex"03");

        (uint256 total, uint256[] memory unitIds) = registry.getUnitIdsByGroupKey(GPUB, 0, 2, false);
        assertEq(total, 3);
        assertEq(unitIds.length, 2);
        assertEq(unitIds[0], 0);
        assertEq(unitIds[1], 1);

        (, unitIds) = registry.getUnitIdsByGroupKey(GPUB, 0, 10, true);
        assertEq(unitIds[0], 2);

        (total, unitIds) = registry.getUnitIdsByGroupKey(GPUB, 9, 10, false);
        assertEq(total, 3);
        assertEq(unitIds.length, 0);

        assertEq(registry.getTotalUnitsByGroupKey(PUB7), 0);
    }

    // ── Possession proofs: group binds content, members bind the group ─────

    function test_wrongKeySignature_reverts() public {
        // PRIV2 signs PUB1's member challenge, but the claimed key is PUB1:
        // possession fails.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 binding = registry.memberBindingFor(GPUB, "");
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", _proofOver(PRIV2, registry.challengeFor("rp1", PUB1, binding), "rp1", 0x05)
        );
        WebAuthnP256PublicKeyRegistry.Proof memory gp1 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp1, members);
    }

    function test_proofBindsItsKey_notReusableForAnotherKey() public {
        // A valid proof for PUB1 cannot authorize storing PUB2, even inside
        // a unit the group key properly signed.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        members[0].publicKey = PUB2;
        WebAuthnP256PublicKeyRegistry.Proof memory gp2 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp2, members);
    }

    function test_replayIsInert() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory groupProof = _groupProof("rp1", hex"aa", members);
        registry.register("rp1", hex"aa", GPUB, groupProof, members);

        // Identical replay: idempotent, rejected by dedup.
        bytes32 contentHash = registry.contentHashFor("rp1", hex"aa", GPUB, members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitAlreadyRegistered.selector, contentHash)
        );
        registry.register("rp1", hex"aa", GPUB, groupProof, members);

        // Altered metadata with the OLD group proof: the group signature
        // binds the content, so a mempool thief cannot re-pair anything.
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"9999", GPUB, groupProof, members);
    }

    function test_membersSignIndependently_groupClosesTheUnit() public {
        // The one-transaction multi-device story: members sign at creation,
        // knowing only the group key and their own fields. The same member
        // proof is valid whatever metadata or siblings the unit ends up
        // with — only the group key's closing signature commits those.
        WebAuthnP256PublicKeyRegistry.Member memory early = _member(PRIV1, PUB1, "", "rp1");

        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](2);
        members[0] = early;
        members[1] = _member(PRIV2, PUB2, ATTESTATION, "rp1");
        registry.register("rp1", hex"beef", GPUB, _groupProof("rp1", hex"beef", members), members);
        assertEq(registry.getTotalEntries(), 2);
        assertTrue(registry.hasEntries(PUB1));
        assertTrue(registry.hasEntries(PUB2));
    }

    function test_memberCannotBeRePairedWithDifferentGroup() public {
        // A member proof binds ITS group key: pairing it with another group
        // (whose own closing signature is perfectly valid) fails.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1"); // bound to GPUB

        bytes32 foreignContent = registry.contentHashFor("rp1", "", PUB7, members);
        WebAuthnP256PublicKeyRegistry.Proof memory foreignGroupProof =
            _proofOver(PRIV7, registry.challengeFor("rp1", PUB7, foreignContent), "rp1", 0x05);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", PUB7, foreignGroupProof, members);
    }

    function test_memberAttestationIsBound() public {
        // Swapping a member's attestation (still shape-valid) breaks that
        // member's binding even when the group re-signs the new content.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        members[0].attestation = ATTESTATION; // signed for "", claimed with ATTESTATION
        WebAuthnP256PublicKeyRegistry.Proof memory gp3 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp3, members);
    }

    function test_rpIdIsBound_throughChallengeAndAuthData() public {
        // Proofs made for rp1 cannot store under rp2: the challenges differ
        // AND the authenticatorData rpIdHash mismatches.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory groupProof = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.RpIdMismatch.selector);
        registry.register("rp2", "", GPUB, groupProof, members);
    }

    function test_userPresentFlagRequired() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        bytes32 binding = registry.memberBindingFor(GPUB, "");
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", _proofOver(PRIV1, registry.challengeFor("rp1", PUB1, binding), "rp1", 0x04)
        );
        WebAuthnP256PublicKeyRegistry.Proof memory gp4 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp4, members);
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
        WebAuthnP256PublicKeyRegistry.Proof memory gp5 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp5, members);
    }

    function test_challengeIndexBeyondClientData_reverts() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        members[0].proof.challengeIndex = 10_000; // far past the JSON's end
        WebAuthnP256PublicKeyRegistry.Proof memory gp6 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp6, members);
    }

    function test_identicalContent_registersOnlyOnce() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");
        // Fresh signatures over the same content change nothing: the
        // content hash is the identity, and it is already taken.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        bytes32 contentHash = registry.contentHashFor("rp1", hex"aa", GPUB, members);
        WebAuthnP256PublicKeyRegistry.Proof memory gp7 = _groupProof("rp1", hex"aa", members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitAlreadyRegistered.selector, contentHash)
        );
        registry.register("rp1", hex"aa", GPUB, gp7, members);
    }

    // ── Atomic multi-member units ──────────────────────────────────────────

    function test_multiMember_everyMemberProves_sharedMetadata() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        registry.register("rp1", hex"1234", GPUB, _groupProof("rp1", hex"1234", members), members);

        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalEntries(), 3);
        // Entries are contiguous and share the unit's metadata and group.
        WebAuthnP256PublicKeyRegistry.EntryView memory second = registry.getEntry(1);
        assertEq(second.publicKey, PUB2);
        assertEq(second.metadata, hex"1234");
        assertEq(second.groupPublicKey, GPUB);
        assertEq(second.firstEntryId, 0);
        assertEq(second.memberCount, 3);
        assertTrue(registry.hasEntries(PUB3));
    }

    function test_multiMember_oneBadProofRevertsAll() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        members[2].proof = members[1].proof; // member 3 carries member 2's signature
        WebAuthnP256PublicKeyRegistry.Proof memory gp8 = _groupProof("rp1", hex"1234", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"1234", GPUB, gp8, members);
        assertEq(registry.getTotalEntries(), 0);
        assertFalse(registry.hasEntries(PUB1));
        // Nothing consumed (state reverted): correct proofs retry fine.
        WebAuthnP256PublicKeyRegistry.Member[] memory fixedMembers = _trio("rp1");
        registry.register("rp1", hex"1234", GPUB, _groupProof("rp1", hex"1234", fixedMembers), fixedMembers);
        assertTrue(registry.hasEntries(PUB1));
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
        uint256[7] memory privs = [PRIV1, PRIV2, PRIV3, PRIV4, PRIV5, PRIV6, PRIV7];
        bytes[7] memory pubs = [PUB1, PUB2, PUB3, PUB4, PUB5, PUB6, PUB7];
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](7);
        for (uint256 i = 0; i < 7; i++) {
            members[i] = _member(privs[i], pubs[i], "", "rp1");
        }
        registry.register("rp1", hex"beef", GPUB, _groupProof("rp1", hex"beef", members), members);
        assertEq(registry.getTotalEntries(), 7);
        assertEq(registry.getTotalEntriesByKey(PUB1), 1);
        assertEq(registry.getTotalEntriesByKey(PUB7), 1);
        assertEq(registry.getTotalUnitsByGroupKey(GPUB), 1);
    }

    function test_duplicateMemberKeyRejected() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](2);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        members[1] = _member(PRIV1, PUB1, "", "rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory gp9 = _groupProof("rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.DuplicateMemberKey.selector, 1));
        registry.register("rp1", "", GPUB, gp9, members);
    }

    function test_groupKeyCannotAlsoBeAMember() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(GPRIV, GPUB, "", "rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory gp10 = _groupProof("rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.DuplicateMemberKey.selector, 0));
        registry.register("rp1", "", GPUB, gp10, members);
    }

    // ── Validation ─────────────────────────────────────────────────────────

    function test_validationBounds() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");

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
        assertEq(registry.getEntry(0).metadata.length, 2048);
    }

    function test_attestationShape() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB1, new bytes(19), _emptyProof());
        WebAuthnP256PublicKeyRegistry.Proof memory gp11 = _groupProof("rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 19));
        registry.register("rp1", "", GPUB, gp11, members);

        bytes memory wrongVersion = ATTESTATION;
        wrongVersion[0] = 0x02;
        members[0].attestation = wrongVersion;
        WebAuthnP256PublicKeyRegistry.Proof memory gp12 = _groupProof("rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 20));
        registry.register("rp1", "", GPUB, gp12, members);
    }

    function test_publicKeyShape() public {
        WebAuthnP256PublicKeyRegistry.Proof memory dummy = _emptyProof();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);

        members[0] = WebAuthnP256PublicKeyRegistry.Member(hex"0400", "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp13 = _groupProof("rp1", "", members);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyLength.selector, 2));
        registry.register("rp1", "", GPUB, gp13, members);

        bytes memory badPrefix = PUB1;
        badPrefix[0] = 0x02;
        members[0] = WebAuthnP256PublicKeyRegistry.Member(badPrefix, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp14 = _groupProof("rp1", "", members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPrefix.selector, bytes1(0x02))
        );
        registry.register("rp1", "", GPUB, gp14, members);

        bytes memory offCurve = bytes.concat(hex"04", bytes32(uint256(1)), bytes32(uint256(1)));
        members[0] = WebAuthnP256PublicKeyRegistry.Member(offCurve, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp15 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPoint.selector);
        registry.register("rp1", "", GPUB, gp15, members);

        bytes memory outOfField = bytes.concat(hex"04", bytes32(type(uint256).max), bytes32(uint256(1)));
        members[0] = WebAuthnP256PublicKeyRegistry.Member(outOfField, "", dummy);
        WebAuthnP256PublicKeyRegistry.Proof memory gp16 = _groupProof("rp1", "", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyCoordinate.selector);
        registry.register("rp1", "", GPUB, gp16, members);

        // The group key gets the same shape validation.
        WebAuthnP256PublicKeyRegistry.Member[] memory ok = new WebAuthnP256PublicKeyRegistry.Member[](1);
        ok[0] = _member(PRIV1, PUB1, "", "rp1");
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyLength.selector, 2));
        registry.register("rp1", "", hex"0400", _emptyProof(), ok);
    }

    // ── Reads, pagination, enumeration ─────────────────────────────────────

    function test_pagination_slicesAndOrders() public {
        _register(PRIV1, PUB1, "rp1", hex"01");
        _register(PRIV1, PUB1, "rp1", hex"02");
        _register(PRIV1, PUB1, "rp1", hex"03");

        (uint256 total, WebAuthnP256PublicKeyRegistry.EntryView[] memory page) =
            registry.getEntriesByKey(PUB1, 1, 1, false);
        assertEq(total, 3);
        assertEq(page.length, 1);
        assertEq(page[0].metadata, hex"02");

        (, page) = registry.getEntriesByKey(PUB1, 0, 2, true);
        assertEq(page[0].metadata, hex"03");
        assertEq(page[1].metadata, hex"02");

        (, page) = registry.getEntriesByKey(PUB1, 100, 10, false);
        assertEq(page.length, 0);
    }

    function test_rpIdEnumeration() public {
        _register(PRIV1, PUB1, "rp1", hex"01");
        _register(PRIV2, PUB2, "rp1", hex"02");
        _register(PRIV3, PUB3, "rp2", hex"03");

        assertEq(registry.getTotalRpIds(), 2);
        assertEq(registry.getTotalEntriesByRpId("rp1"), 2);
        assertEq(registry.getTotalEntriesByRpId("rp2"), 1);
        (uint256 total, string[] memory rpIds, uint256[] memory counts,) = registry.getRpIds(0, 10, false);
        assertEq(total, 2);
        assertEq(rpIds[0], "rp1");
        assertEq(counts[0], 2);
        assertEq(rpIds[1], "rp2");
        assertEq(counts[1], 1);

        // Past-the-end page: totals stay, slices are empty.
        (total, rpIds, counts,) = registry.getRpIds(5, 10, false);
        assertEq(total, 2);
        assertEq(rpIds.length, 0);

        (, WebAuthnP256PublicKeyRegistry.EntryView[] memory records) = registry.getEntriesByRpId("rp1", 0, 10, true);
        assertEq(records[0].metadata, hex"02");
    }

    function test_getEntryAndUnit_outOfRangeRevert() public {
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.EntryNotFound.selector, 0));
        registry.getEntry(0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitNotFound.selector, 0));
        registry.getUnit(0);
    }

    // ── Ids are stable forever ─────────────────────────────────────────────

    function test_ids_areSequentialAndImmutable() public {
        _register(PRIV1, PUB1, "rp1", hex"01");
        WebAuthnP256PublicKeyRegistry.Member[] memory trio = _trio("rp2");
        registry.register("rp2", hex"0202", GPUB, _groupProof("rp2", hex"0202", trio), trio);
        WebAuthnP256PublicKeyRegistry.EntryView memory before = registry.getEntry(0);
        _register(PRIV3, PUB3, "rp3", hex"03");
        WebAuthnP256PublicKeyRegistry.EntryView memory later = registry.getEntry(0);
        assertEq(later.publicKey, before.publicKey);
        assertEq(later.metadata, before.metadata);
        assertEq(registry.getTotalEntries(), 5);
        assertEq(registry.getTotalUnits(), 3);
        // The trio unit's entries are contiguous starting at entry 1, and
        // its unit carries the group key.
        WebAuthnP256PublicKeyRegistry.Unit memory unit = registry.getUnit(1);
        assertEq(unit.firstEntryId, 1);
        assertEq(unit.memberCount, 3);
        assertEq(unit.groupPublicKey, GPUB);
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
        // Proofs made for one registry instance are dead on another: the
        // challenge commits to address(registry).
        WebAuthnP256PublicKeyRegistry other = new WebAuthnP256PublicKeyRegistry();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1"); // signed for `registry`
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof("rp1", "", members);

        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        other.register("rp1", "", GPUB, gp, members);

        registry.register("rp1", "", GPUB, gp, members); // home instance still fine
        assertEq(registry.getTotalUnits(), 1);
    }

    function test_challengeBindsChainId() public {
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "", "rp1");
        WebAuthnP256PublicKeyRegistry.Proof memory gp = _groupProof("rp1", "", members);

        vm.chainId(31338); // a fork with a different chain id rejects them
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", GPUB, gp, members);
    }

    function test_memberReorder_isDifferentContent() public {
        // Reordering members changes the content hash: the old group proof
        // dies with the order, and a re-signed reorder is a distinct unit.
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1");
        registry.register("rp1", hex"1234", GPUB, _groupProof("rp1", hex"1234", members), members);

        WebAuthnP256PublicKeyRegistry.Member[] memory reordered = new WebAuthnP256PublicKeyRegistry.Member[](3);
        (reordered[0], reordered[1], reordered[2]) = (members[1], members[0], members[2]);
        WebAuthnP256PublicKeyRegistry.Proof memory staleGroupProof = _groupProof("rp1", hex"1234", members);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"1234", GPUB, staleGroupProof, reordered);

        registry.register("rp1", hex"1234", GPUB, _groupProof("rp1", hex"1234", reordered), reordered);
        assertEq(registry.getTotalUnits(), 2);
    }
}
