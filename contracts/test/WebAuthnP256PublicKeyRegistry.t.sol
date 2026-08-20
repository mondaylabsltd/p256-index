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

    // v1 || AAGUID || authData flags 0x5d || platform || usb|internal
    bytes constant ATTESTATION = hex"01fbfc3007154e4ecc8c0b6e020557d7bd5d0109";

    uint256 private _nonceCounter;

    function setUp() public {
        // Stand in for the EIP-7951 / RIP-7212 precompile (live on Gnosis,
        // absent in the local EVM) with the audited Solidity fallback.
        vm.etch(address(0x100), address(new P256Verifier()).code);
        registry = new WebAuthnP256PublicKeyRegistry();
    }

    // ── Proof construction (real signatures) ───────────────────────────────

    function _freshNonce() internal returns (bytes32) {
        return keccak256(abi.encode("nonce", _nonceCounter++));
    }

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

    /// One member signing its own storage-authorization challenge — exactly
    /// what each device does right after creating its passkey.
    function _member(uint256 priv, bytes memory pubkey, string memory rpId, bytes32 nonce)
        internal
        view
        returns (WebAuthnP256PublicKeyRegistry.Member memory)
    {
        bytes32 challenge = registry.challengeFor(rpId, pubkey, nonce);
        return WebAuthnP256PublicKeyRegistry.Member(pubkey, "", _proofOver(priv, challenge, rpId, 0x05));
    }

    function _register(uint256 priv, bytes memory pubkey, string memory rpId, bytes memory metadata)
        internal
        returns (bytes32 nonce)
    {
        nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(priv, pubkey, rpId, nonce);
        registry.register(rpId, metadata, nonce, members);
    }

    function _trio(string memory rpId, bytes32 nonce)
        internal
        view
        returns (WebAuthnP256PublicKeyRegistry.Member[] memory members)
    {
        members = new WebAuthnP256PublicKeyRegistry.Member[](3);
        members[0] = _member(PRIV1, PUB1, rpId, nonce);
        members[1] = _member(PRIV2, PUB2, rpId, nonce);
        members[2] = _member(PRIV3, PUB3, rpId, nonce);
    }

    // ── Happy path ─────────────────────────────────────────────────────────

    function test_register_storesAndIndexes() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);
        members[0].attestation = ATTESTATION;

        vm.expectEmit(true, true, false, true);
        emit WebAuthnP256PublicKeyRegistry.UnitRegistered(0, keccak256(bytes("rp1")), 0, 1);
        registry.register("rp1", hex"aa", nonce, members);

        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalEntries(), 1);
        WebAuthnP256PublicKeyRegistry.EntryView memory entry = registry.getEntry(0);
        assertEq(entry.publicKey, PUB1);
        assertEq(entry.rpId, "rp1");
        assertEq(entry.metadata, hex"aa");
        assertEq(entry.attestation, ATTESTATION);
        assertEq(entry.unitId, 0);
        assertEq(entry.memberCount, 1);
        assertTrue(registry.hasEntries(PUB1));
        assertTrue(registry.isNonceUsed(nonce));
        assertTrue(registry.isContentRegistered(registry.contentHashFor("rp1", hex"aa", members)));
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
    }

    function test_unregisteredKey_hasNothing() public {
        _register(PRIV1, PUB1, "rp1", "");
        assertFalse(registry.hasEntries(PUB2));
        (uint256 total,) = registry.getEntriesByKey(PUB2, 0, 10, false);
        assertEq(total, 0);
    }

    // ── Possession proofs: storage authorization per key ───────────────────

    function test_wrongKeySignature_reverts() public {
        // PRIV2 signs PUB1's challenge, but the claimed key is PUB1:
        // possession fails.
        bytes32 nonce = _freshNonce();
        bytes32 challenge = registry.challengeFor("rp1", PUB1, nonce);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB1, "", _proofOver(PRIV2, challenge, "rp1", 0x05));
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", nonce, members);
    }

    function test_proofBindsItsKey_notReusableForAnotherKey() public {
        // A valid proof for PUB1 cannot authorize storing PUB2.
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member memory m1 = _member(PRIV1, PUB1, "rp1", nonce);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB2, "", m1.proof);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", nonce, members);
    }

    function test_proofsDieWithTheirNonce() public {
        // After a unit is mined its proofs are public — but the nonce is
        // consumed, so replaying them (same nonce, any content) reverts,
        // and a different nonce changes the challenge so they fail there too.
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);
        registry.register("rp1", hex"aa", nonce, members);

        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.NonceAlreadyUsed.selector, nonce));
        registry.register("rp1", hex"9999", nonce, members);

        bytes32 fresh = _freshNonce();
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"9999", fresh, members);
    }

    function test_contentIsNotBoundBySignatures_byDesign() public {
        // The documented trust model: a proof authorizes storing its key,
        // not the unit's content. The same in-flight proof set is valid for
        // any metadata (content immutability comes from mining + nonce
        // consumption, not from the signatures).
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);
        registry.register("rp1", hex"beefbeef", nonce, members);
        assertEq(registry.getEntry(0).metadata, hex"beefbeef");
    }

    function test_rpIdIsBound_throughChallengeAndAuthData() public {
        // A proof made for rp1 cannot store under rp2: the challenge differs
        // AND the authenticatorData rpIdHash mismatches.
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member memory m1 = _member(PRIV1, PUB1, "rp1", nonce);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = m1;
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.RpIdMismatch.selector);
        registry.register("rp2", "", nonce, members);
    }

    function test_userPresentFlagRequired() public {
        bytes32 nonce = _freshNonce();
        bytes32 challenge = registry.challengeFor("rp1", PUB1, nonce);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(PUB1, "", _proofOver(PRIV1, challenge, "rp1", 0x04));
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", nonce, members);
    }

    function test_wrongCeremonyType_reverts() public {
        bytes32 nonce = _freshNonce();
        bytes32 challenge = registry.challengeFor("rp1", PUB1, nonce);
        string memory clientData =
            string.concat('{"type":"webauthn.create","challenge":"', Base64Url.encode32(challenge), '"}');
        bytes memory authData = _authData("rp1", 0x05);
        bytes32 digest = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));
        (bytes32 r, bytes32 s) = vm.signP256(PRIV1, digest);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = WebAuthnP256PublicKeyRegistry.Member(
            PUB1, "", WebAuthnP256PublicKeyRegistry.Proof(authData, clientData, 26, 1, uint256(r), uint256(s))
        );
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", "", nonce, members);
    }

    function test_identicalContent_registersOnlyOnce() public {
        _register(PRIV1, PUB1, "rp1", hex"aa");
        // Fresh nonce, fresh signature — identical content is still refused.
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);
        bytes32 contentHash = registry.contentHashFor("rp1", hex"aa", members);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.UnitAlreadyRegistered.selector, contentHash)
        );
        registry.register("rp1", hex"aa", nonce, members);
    }

    // ── Atomic multi-member units ──────────────────────────────────────────

    function test_multiMember_everyMemberProves_sharedMetadata() public {
        bytes32 nonce = _freshNonce();
        registry.register("rp1", hex"1234", nonce, _trio("rp1", nonce));

        assertEq(registry.getTotalUnits(), 1);
        assertEq(registry.getTotalEntries(), 3);
        // Entries are contiguous and share the unit's metadata.
        WebAuthnP256PublicKeyRegistry.EntryView memory second = registry.getEntry(1);
        assertEq(second.publicKey, PUB2);
        assertEq(second.metadata, hex"1234");
        assertEq(second.firstEntryId, 0);
        assertEq(second.memberCount, 3);
        assertTrue(registry.hasEntries(PUB3));
    }

    function test_multiMember_oneBadProofRevertsAll() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = _trio("rp1", nonce);
        members[2].proof = members[1].proof; // member 3 carries member 2's signature
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidProof.selector);
        registry.register("rp1", hex"1234", nonce, members);
        assertEq(registry.getTotalEntries(), 0);
        assertFalse(registry.hasEntries(PUB1));
        // Nonce not consumed (state reverted): the unit can retry.
        assertFalse(registry.isNonceUsed(nonce));
    }

    function test_memberCountBounds() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory none = new WebAuthnP256PublicKeyRegistry.Member[](0);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidMemberCount.selector, 0));
        registry.register("rp1", "", nonce, none);

        WebAuthnP256PublicKeyRegistry.Member[] memory eight = new WebAuthnP256PublicKeyRegistry.Member[](8);
        for (uint256 i = 0; i < 8; i++) {
            eight[i] = _member(PRIV1, PUB1, "rp1", nonce);
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidMemberCount.selector, 8));
        registry.register("rp1", "", nonce, eight);
    }

    function test_sevenMembersFit() public {
        bytes32 nonce = _freshNonce();
        uint256[3] memory privs = [PRIV1, PRIV2, PRIV3];
        bytes[3] memory pubs = [PUB1, PUB2, PUB3];
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](7);
        for (uint256 i = 0; i < 7; i++) {
            members[i] = _member(privs[i % 3], pubs[i % 3], "rp1", nonce);
        }
        registry.register("rp1", hex"beef", nonce, members);
        assertEq(registry.getTotalEntries(), 7);
        assertEq(registry.getTotalEntriesByKey(PUB1), 3);
    }

    // ── Validation ─────────────────────────────────────────────────────────

    function test_validationBounds() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);

        vm.expectRevert(WebAuthnP256PublicKeyRegistry.EmptyRpId.selector);
        registry.register("", "", nonce, members);

        string memory longRp = string(new bytes(254));
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.RpIdTooLong.selector, 254));
        registry.register(longRp, "", nonce, members);

        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.MetadataTooLong.selector, 1025));
        registry.register("rp1", new bytes(1025), nonce, members);
    }

    function test_metadataAtCapRegisters() public {
        _register(PRIV1, PUB1, "rp1", new bytes(1024));
        assertEq(registry.getEntry(0).metadata.length, 1024);
    }

    function test_attestationShape() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);
        members[0] = _member(PRIV1, PUB1, "rp1", nonce);

        members[0].attestation = new bytes(19);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 19));
        registry.register("rp1", "", nonce, members);

        bytes memory wrongVersion = ATTESTATION;
        wrongVersion[0] = 0x02;
        members[0].attestation = wrongVersion;
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidAttestation.selector, 20));
        registry.register("rp1", "", nonce, members);
    }

    function test_publicKeyShape() public {
        bytes32 nonce = _freshNonce();
        WebAuthnP256PublicKeyRegistry.Proof memory dummy = _proofOver(PRIV1, bytes32(0), "rp1", 0x05);
        WebAuthnP256PublicKeyRegistry.Member[] memory members = new WebAuthnP256PublicKeyRegistry.Member[](1);

        members[0] = WebAuthnP256PublicKeyRegistry.Member(hex"0400", "", dummy);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyLength.selector, 2));
        registry.register("rp1", "", nonce, members);

        bytes memory badPrefix = PUB1;
        badPrefix[0] = 0x02;
        members[0] = WebAuthnP256PublicKeyRegistry.Member(badPrefix, "", dummy);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPrefix.selector, bytes1(0x02))
        );
        registry.register("rp1", "", nonce, members);

        bytes memory offCurve = bytes.concat(hex"04", bytes32(uint256(1)), bytes32(uint256(1)));
        members[0] = WebAuthnP256PublicKeyRegistry.Member(offCurve, "", dummy);
        vm.expectRevert(WebAuthnP256PublicKeyRegistry.InvalidPublicKeyPoint.selector);
        registry.register("rp1", "", nonce, members);
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
        (uint256 total, string[] memory rpIds, uint256[] memory counts,) = registry.getRpIds(0, 10, false);
        assertEq(total, 2);
        assertEq(rpIds[0], "rp1");
        assertEq(counts[0], 2);
        assertEq(rpIds[1], "rp2");
        assertEq(counts[1], 1);

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
        bytes32 nonce = _freshNonce();
        registry.register("rp2", hex"0202", nonce, _trio("rp2", nonce));
        WebAuthnP256PublicKeyRegistry.EntryView memory before = registry.getEntry(0);
        _register(PRIV3, PUB3, "rp3", hex"03");
        WebAuthnP256PublicKeyRegistry.EntryView memory later = registry.getEntry(0);
        assertEq(later.publicKey, before.publicKey);
        assertEq(later.metadata, before.metadata);
        assertEq(registry.getTotalEntries(), 5);
        assertEq(registry.getTotalUnits(), 3);
        // The trio unit's entries are contiguous starting at entry 1.
        WebAuthnP256PublicKeyRegistry.Unit memory unit = registry.getUnit(1);
        assertEq(unit.firstEntryId, 1);
        assertEq(unit.memberCount, 3);
    }
}
