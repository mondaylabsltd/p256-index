// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";
import {WebAuthnP256PublicKeyIndexV3} from "../src/WebAuthnP256PublicKeyIndexV3.sol";

/// Stand-in for a misbehaving contract at the V2 address: every call reverts
/// with an error that is NOT WalletRefNotFound.
contract RevertingV2Mock {
    error Unexpected();

    fallback() external {
        revert Unexpected();
    }
}

contract WebAuthnP256PublicKeyIndexV3Test is Test {
    WebAuthnP256PublicKeyIndexV3 public index;

    bytes constant PK1 =
        hex"045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
    bytes constant PK2 =
        hex"04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6";
    bytes constant PK3 =
        hex"04dff13c9668fd5ddc5022e9eb6f04be68a5ded7e40a61a84e35ee26ec675f995b20f1f64466711963e4f758bf5abaf12f569716cdc146a1c0cc8990d41d2f92fb";
    bytes32 constant PREFIX = "VelaWalletV1";
    uint256 private _walletRefCounter = 1;

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndexV3();
    }

    // ── Helpers ──

    function _nextWalletRef() internal returns (bytes32) {
        return bytes32(_walletRefCounter++);
    }

    /// Single-key metadata: bytes32("VelaWalletV1") || pk
    function _meta(bytes memory pk) internal pure returns (bytes memory) {
        return abi.encodePacked(PREFIX, pk);
    }

    /// V2-era metadata encoding (what production V2 records actually carry)
    function _legacyMeta(bytes memory pk) internal pure returns (bytes memory) {
        return abi.encode("VelaWalletV1", pk);
    }

    /// The single-record commitment, identical for V2 and V3 (7 fields).
    function _commitment(
        string memory rpId,
        string memory credentialId,
        bytes32 walletRef,
        bytes memory pk,
        string memory name,
        string memory initialCredentialId,
        bytes memory metadata
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(rpId, credentialId, walletRef, pk, name, initialCredentialId, metadata));
    }

    /// The wallet-bundle commitment: one commit covers all members.
    function _walletCommitment(
        string memory rpId,
        bytes32 walletRef,
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(index.WALLET_COMMIT_TAG(), rpId, walletRef, members));
    }

    function _commitOnly(
        string memory rpId,
        string memory credentialId,
        bytes32 walletRef,
        bytes memory pk,
        string memory name,
        string memory initialCredentialId,
        bytes memory metadata
    ) internal {
        index.commit(_commitment(rpId, credentialId, walletRef, pk, name, initialCredentialId, metadata));
        vm.roll(block.number + 2);
    }

    /// Single-key wallet registration (commit + reveal).
    function _createRecordWithRef(
        string memory rpId,
        string memory credentialId,
        bytes memory pk,
        string memory name,
        bytes32 walletRef
    ) internal {
        _commitOnly(rpId, credentialId, walletRef, pk, name, credentialId, _meta(pk));
        index.createRecord(rpId, credentialId, walletRef, pk, name, credentialId, _meta(pk));
    }

    function _createInitialRecord(string memory rpId, string memory credentialId, bytes memory pk, string memory name)
        internal
    {
        _createRecordWithRef(rpId, credentialId, pk, name, _nextWalletRef());
    }

    function _members2(string memory c1, string memory c2)
        internal
        pure
        returns (WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members)
    {
        members = new WebAuthnP256PublicKeyIndexV3.WalletMember[](2);
        members[0] = WebAuthnP256PublicKeyIndexV3.WalletMember(c1, PK1, "A");
        members[1] = WebAuthnP256PublicKeyIndexV3.WalletMember(c2, PK2, "B");
    }

    function _members3() internal pure returns (WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members) {
        members = new WebAuthnP256PublicKeyIndexV3.WalletMember[](3);
        members[0] = WebAuthnP256PublicKeyIndexV3.WalletMember("cred-1", PK1, "A");
        members[1] = WebAuthnP256PublicKeyIndexV3.WalletMember("cred-2", PK2, "B");
        members[2] = WebAuthnP256PublicKeyIndexV3.WalletMember("cred-3", PK3, "C");
    }

    /// Multi-key wallet registration (one commit + one atomic reveal).
    function _createWallet(
        bytes32 walletRef,
        string memory rpId,
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members
    ) internal {
        index.commit(_walletCommitment(rpId, walletRef, members));
        vm.roll(block.number + 2);
        index.createWallet(rpId, walletRef, members);
    }

    // ── Version ──

    function test_version() public view {
        assertEq(index.VERSION(), 3);
    }

    // ── Create & Query (single-key path) ──

    function test_createAndQuery() public {
        _createInitialRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc", PK1, "My Passkey");

        WebAuthnP256PublicKeyIndexV3.PublicKeyRecord memory r =
            index.getRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc");

        assertEq(r.rpId, "btc5m.crazydoge.dev");
        assertEq(r.credentialId, "paRIU_PWELwa1kf8R2-2yw54mIc");
        assertEq(r.publicKey, PK1);
        assertEq(r.name, "My Passkey");
        assertEq(r.initialCredentialId, "paRIU_PWELwa1kf8R2-2yw54mIc");
        assertGt(r.createdAt, 0);
    }

    function test_createdAt_usesBlockTimestamp() public {
        vm.warp(1700000000);
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        assertEq(index.getRecord("rp1", "cred-1").createdAt, 1700000000);
    }

    function test_createdAtZero_stillExistsAndDoesNotDuplicateRpId() public {
        vm.warp(0);
        _createInitialRecord("rp-zero", "cred-1", PK1, "Zero timestamp");

        assertEq(index.getRecord("rp-zero", "cred-1").createdAt, 0);
        assertTrue(index.hasRecord("rp-zero", "cred-1"));

        _createInitialRecord("rp-zero", "cred-2", PK2, "Second zero timestamp");
        assertEq(index.getTotalRpIds(), 1);
        assertEq(index.getTotalCredentialsByRpId("rp-zero"), 2);
    }

    function test_sameCredentialId_differentRpId() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Key on rp1");
        _createInitialRecord("rp2", "cred-1", PK2, "Key on rp2");

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
        assertEq(index.getRecord("rp2", "cred-1").publicKey, PK2);
    }

    function test_appendOnly_cannotOverwrite() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");

        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-1", a, PK2, "Key 2", "cred-1", _meta(PK2));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordAlreadyExists.selector, "rp1", "cred-1")
        );
        index.createRecord("rp1", "cred-1", a, PK2, "Key 2", "cred-1", _meta(PK2));

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
    }

    function test_emptyName_allowed() public {
        _createInitialRecord("rp1", "cred-1", PK1, "");
        assertEq(bytes(index.getRecord("rp1", "cred-1").name).length, 0);
    }

    function test_unicodeName() public {
        _createInitialRecord("rp1", "cred-1", PK1, unicode"我的密钥🔑");
        assertEq(index.getRecord("rp1", "cred-1").name, unicode"我的密钥🔑");
    }

    // ── createWallet: atomic multi-key registration ──

    function test_createWallet_registersAllMembersAtomically() public {
        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");

        vm.recordLogs();
        _createWallet(w, "rp1", members);

        // Two RecordCreated (one per member) followed by one WalletCreated.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 3);
        assertEq(logs[2].topics[0], WebAuthnP256PublicKeyIndexV3.WalletCreated.selector);
        assertEq(logs[2].topics[1], w);

        assertEq(index.getTotalCredentials(), 2);
        assertEq(index.getTotalWallets(), 1);
        assertEq(index.getTotalCredentialsByWalletRef(w), 2);

        // The credentialId array is queryable, in registration order.
        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getRecordsByWalletRef(w, 0, 10, false);
        assertEq(total, 2);
        assertEq(records[0].credentialId, "cred-1");
        assertEq(records[1].credentialId, "cred-2");

        // Metadata is built on-chain from the ordered member keys, identical
        // on every member record.
        bytes memory expectedMeta = abi.encodePacked(PREFIX, PK1, PK2);
        assertEq(records[0].metadata, expectedMeta);
        assertEq(records[1].metadata, expectedMeta);
        assertEq(records[1].publicKey, PK2);
        assertEq(records[1].initialCredentialId, "cred-2"); // members are self-rooted
    }

    function test_walletCommitment_goldenValue() public view {
        // Cross-language pin: the Rust registrar's build_wallet_commitment
        // asserts this exact value for the same inputs.
        assertEq(
            _walletCommitment("rp1", bytes32(uint256(0x42)), _members2("cred-1", "cred-2")),
            0x0bcf64f774f9f6721c25a0e2a2da9288add57fbf8c3625b1c72357f3c54383f2
        );
    }

    function test_createWallet_requiresCommit() public {
        bytes32 w = _nextWalletRef();
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.createWallet("rp1", w, _members2("cred-1", "cred-2"));
    }

    function test_createWallet_commitBindsTheWholeBundle() public {
        // Altering any member between commit and reveal invalidates the commitment.
        bytes32 w = _nextWalletRef();
        index.commit(_walletCommitment("rp1", w, _members2("cred-1", "cred-2")));
        vm.roll(block.number + 2);

        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory altered = _members2("cred-1", "cred-CHANGED");
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.createWallet("rp1", w, altered);
    }

    function test_createWallet_oneCommitOneReveal() public {
        // The bundle commitment is consumed by the reveal: a second identical
        // wallet reveal finds no commitment (and the walletRef is taken anyway).
        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");
        _createWallet(w, "rp1", members);

        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.createWallet("rp1", w, members);
    }

    function test_createWallet_duplicateCredentialIdInBundle_reverts() public {
        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-1");
        index.commit(_walletCommitment("rp1", w, members));
        vm.roll(block.number + 2);

        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordAlreadyExists.selector, "rp1", "cred-1")
        );
        index.createWallet("rp1", w, members);
        // Atomic: nothing landed.
        assertFalse(index.hasRecord("rp1", "cred-1"));
        assertEq(index.getTotalWallets(), 0);
    }

    function test_createWallet_memberCountBounds() public {
        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory none = new WebAuthnP256PublicKeyIndexV3.WalletMember[](0);
        index.commit(_walletCommitment("rp1", w, none));
        vm.roll(block.number + 2);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidMemberCount.selector, 0));
        index.createWallet("rp1", w, none);

        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory tooMany = new WebAuthnP256PublicKeyIndexV3.WalletMember[](22);
        for (uint256 i = 0; i < 22; i++) {
            tooMany[i] =
                WebAuthnP256PublicKeyIndexV3.WalletMember(string(abi.encodePacked("cred-", vm.toString(i))), PK1, "K");
        }
        index.commit(_walletCommitment("rp1", w, tooMany));
        vm.roll(block.number + 2);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidMemberCount.selector, 22));
        index.createWallet("rp1", w, tooMany);
    }

    function test_createWallet_maxMembers_fit() public {
        // 21 members: metadata reaches exactly MAX_METADATA_LENGTH.
        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = new WebAuthnP256PublicKeyIndexV3.WalletMember[](21);
        for (uint256 i = 0; i < 21; i++) {
            members[i] =
                WebAuthnP256PublicKeyIndexV3.WalletMember(string(abi.encodePacked("cred-", vm.toString(i))), PK1, "K");
        }
        _createWallet(w, "rp1", members);

        assertEq(index.getTotalCredentialsByWalletRef(w), 21);
        assertEq(index.getRecordByWalletRef(w).metadata.length, index.MAX_METADATA_LENGTH());
    }

    function test_createWallet_offCurveMemberKey_reverts() public {
        bytes32 w = _nextWalletRef();
        bytes memory badPk =
            hex"04aaa257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");
        members[1].publicKey = badPk;
        index.commit(_walletCommitment("rp1", w, members));
        vm.roll(block.number + 2);
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyPoint.selector);
        index.createWallet("rp1", w, members);
    }

    function test_walletRef_isClaimedExactlyOnce() public {
        // Single then wallet, wallet then single, wallet then wallet: the
        // second claim always fails loudly.
        bytes32 w1 = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-s", PK1, "Single", w1);
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");
        index.commit(_walletCommitment("rp1", w1, members));
        vm.roll(block.number + 2);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefAlreadyExists.selector, w1));
        index.createWallet("rp1", w1, members);

        bytes32 w2 = _nextWalletRef();
        _createWallet(w2, "rp1", members);
        _commitOnly("rp1", "cred-x", w2, PK3, "Late", "cred-x", _meta(PK3));
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefAlreadyExists.selector, w2));
        index.createRecord("rp1", "cred-x", w2, PK3, "Late", "cred-x", _meta(PK3));
    }

    // ── Wallet queries ──

    function test_getRecordByWalletRef_returnsFirstMember() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members2("cred-1", "cred-2"));

        WebAuthnP256PublicKeyIndexV3.PublicKeyRecord memory r = index.getRecordByWalletRef(w);
        assertEq(r.credentialId, "cred-1");
        assertEq(r.metadata, abi.encodePacked(PREFIX, PK1, PK2));
    }

    function test_getRecordsByWalletRef_desc() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members2("cred-1", "cred-2"));

        (, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) = index.getRecordsByWalletRef(w, 0, 10, true);
        assertEq(records[0].credentialId, "cred-2");
        assertEq(records[1].credentialId, "cred-1");
    }

    function test_getRecordsByWalletRef_pagination() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members3());

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory page1) =
            index.getRecordsByWalletRef(w, 0, 2, false);
        assertEq(total, 3);
        assertEq(page1.length, 2);
        assertEq(page1[0].credentialId, "cred-1");
        assertEq(page1[1].credentialId, "cred-2");

        (, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory page2) = index.getRecordsByWalletRef(w, 2, 2, false);
        assertEq(page2.length, 1);
        assertEq(page2[0].credentialId, "cred-3");

        (, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory descPage) = index.getRecordsByWalletRef(w, 1, 1, true);
        assertEq(descPage.length, 1);
        assertEq(descPage[0].credentialId, "cred-2");
    }

    function test_getRecordsByWalletRef_offsetBeyondTotal() public {
        bytes32 w = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "A", w);

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getRecordsByWalletRef(w, 100, 10, false);
        assertEq(total, 1);
        assertEq(records.length, 0);
    }

    function test_getRecordsByWalletRef_unknownRef() public view {
        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getRecordsByWalletRef(bytes32(uint256(999)), 0, 10, false);
        assertEq(total, 0);
        assertEq(records.length, 0);
    }

    function test_getRecordsByWalletRef_limitZero_returnsCountOnly() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members2("cred-1", "cred-2"));

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getRecordsByWalletRef(w, 0, 0, false);
        assertEq(total, 2);
        assertEq(records.length, 0);
    }

    // ── Wallet enumeration & stats ──

    function test_walletAndCredentialCounts_independent() public {
        bytes32 w1 = _nextWalletRef();
        bytes32 w2 = _nextWalletRef();
        _createWallet(w1, "rp1", _members2("cred-1", "cred-2"));
        _createRecordWithRef("rp2", "cred-3", PK3, "W2 only key", w2);

        assertEq(index.getTotalCredentials(), 3);
        assertEq(index.getTotalWallets(), 2);
        assertEq(index.getTotalCredentialsByWalletRef(w1), 2);
        assertEq(index.getTotalCredentialsByWalletRef(w2), 1);
        assertEq(index.getTotalCredentialsByWalletRef(bytes32(uint256(999))), 0);
    }

    function test_getWalletRefs_ascWithCountsAndCreatedAts() public {
        bytes32 w1 = _nextWalletRef();
        bytes32 w2 = _nextWalletRef();
        vm.warp(1000);
        _createWallet(w1, "rp1", _members2("cred-1", "cred-2"));
        vm.warp(2000);
        _createRecordWithRef("rp2", "cred-3", PK3, "W2 only key", w2);

        (uint256 total, bytes32[] memory refs, uint256[] memory counts, uint256[] memory createdAts) =
            index.getWalletRefs(0, 10, false);
        assertEq(total, 2);
        assertEq(refs.length, 2);
        assertEq(refs[0], w1);
        assertEq(refs[1], w2);
        assertEq(counts[0], 2);
        assertEq(counts[1], 1);
        assertEq(createdAts[0], 1000);
        assertEq(createdAts[1], 2000);
    }

    function test_getWalletRefs_desc() public {
        bytes32 w1 = _nextWalletRef();
        bytes32 w2 = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "A", w1);
        _createRecordWithRef("rp1", "cred-2", PK2, "B", w2);

        (uint256 total, bytes32[] memory refs,,) = index.getWalletRefs(0, 10, true);
        assertEq(total, 2);
        assertEq(refs[0], w2);
        assertEq(refs[1], w1);
    }

    function test_getWalletRefs_pagination() public {
        bytes32 w1 = _nextWalletRef();
        bytes32 w2 = _nextWalletRef();
        bytes32 w3 = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "A", w1);
        _createRecordWithRef("rp1", "cred-2", PK2, "B", w2);
        _createRecordWithRef("rp1", "cred-3", PK3, "C", w3);

        (uint256 total, bytes32[] memory page1,,) = index.getWalletRefs(0, 2, false);
        assertEq(total, 3);
        assertEq(page1.length, 2);
        assertEq(page1[0], w1);
        assertEq(page1[1], w2);

        (, bytes32[] memory page2,,) = index.getWalletRefs(2, 2, false);
        assertEq(page2.length, 1);
        assertEq(page2[0], w3);

        (, bytes32[] memory descPage,,) = index.getWalletRefs(1, 1, true);
        assertEq(descPage.length, 1);
        assertEq(descPage[0], w2);
    }

    function test_getWalletRefs_offsetBeyondTotal() public {
        bytes32 w = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "A", w);
        (uint256 total, bytes32[] memory refs,,) = index.getWalletRefs(100, 10, false);
        assertEq(total, 1);
        assertEq(refs.length, 0);
    }

    function test_getWalletRefs_multiKeyWalletListedOnce() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members3());

        (uint256 total, bytes32[] memory refs, uint256[] memory counts,) = index.getWalletRefs(0, 10, false);
        assertEq(total, 1);
        assertEq(refs[0], w);
        assertEq(counts[0], 3);
    }

    // ── Credential-key uniqueness ──

    function test_sameCredentialKey_absorbedAtMostOnce() public {
        // k = keccak(rpId, credentialId) is claimed exactly once, ever:
        // RecordAlreadyExists fires before any state write and records are
        // append-only, so a wallet's member list can never hold duplicates.
        bytes32 w = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "First", w);

        bytes32 other = _nextWalletRef();
        _commitOnly("rp1", "cred-1", other, PK2, "Replay", "cred-1", _meta(PK2));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordAlreadyExists.selector, "rp1", "cred-1")
        );
        index.createRecord("rp1", "cred-1", other, PK2, "Replay", "cred-1", _meta(PK2));

        assertEq(index.getTotalCredentials(), 1);
        assertEq(index.getTotalCredentialsByWalletRef(w), 1);
    }

    function testFuzz_counters_stayAccurate(uint256 seed, uint8 countRaw) public {
        // Random mix of single-key and multi-key wallets; the test tallies
        // expected credentials and wallets independently.
        uint256 budget = bound(uint256(countRaw), 1, 12);
        uint256 credSerial;
        uint256 expectedWallets;
        bytes[3] memory pks = [PK1, PK2, PK3];

        uint256 round;
        while (budget > 0) {
            uint256 size = 1 + (uint256(keccak256(abi.encode(seed, round))) % 3);
            if (size > budget) size = budget;
            bytes32 w = _nextWalletRef();

            if (size == 1) {
                string memory cred = string(abi.encodePacked("cred-", vm.toString(credSerial++)));
                _createRecordWithRef("rp1", cred, PK1, "K", w);
            } else {
                WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members =
                    new WebAuthnP256PublicKeyIndexV3.WalletMember[](size);
                for (uint256 m = 0; m < size; m++) {
                    members[m] = WebAuthnP256PublicKeyIndexV3.WalletMember(
                        string(abi.encodePacked("cred-", vm.toString(credSerial++))), pks[m], "K"
                    );
                }
                _createWallet(w, "rp1", members);
            }
            expectedWallets++;
            budget -= size;
            round++;
        }

        assertEq(index.getTotalCredentials(), credSerial);
        assertEq(index.getTotalWallets(), expectedWallets);
    }

    // ── Single-path metadata strictness ──

    function test_revert_metadataNotOwnSingleKey() public {
        // createRecord accepts exactly bytes32("VelaWalletV1") || own key.
        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-1", a, PK1, "K", "cred-1", _meta(PK2)); // someone else's key
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.MetadataNotOwnSingleKey.selector);
        index.createRecord("rp1", "cred-1", a, PK1, "K", "cred-1", _meta(PK2));

        bytes memory twoKeys = abi.encodePacked(PREFIX, PK1, PK2);
        _commitOnly("rp1", "cred-1", a, PK1, "K", "cred-1", twoKeys); // multi-key set
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.MetadataNotOwnSingleKey.selector);
        index.createRecord("rp1", "cred-1", a, PK1, "K", "cred-1", twoKeys);
    }

    function test_revert_metadata_emptyOrLegacyRejected() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.MetadataNotOwnSingleKey.selector);
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), PK1, "bad", "cred-1", "");

        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.MetadataNotOwnSingleKey.selector);
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), PK1, "bad", "cred-1", _legacyMeta(PK1));
    }

    // ── initialCredentialId validation ──

    function test_initialKey_selfReference() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Initial");
        assertEq(index.getRecord("rp1", "cred-1").initialCredentialId, "cred-1");
    }

    function test_rotatedKey_referencesExisting() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Initial");

        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-2", a, PK2, "Rotated", "cred-1", _meta(PK2));
        index.createRecord("rp1", "cred-2", a, PK2, "Rotated", "cred-1", _meta(PK2));

        assertEq(index.getRecord("rp1", "cred-2").initialCredentialId, "cred-1");
    }

    function test_revert_initialCredentialId_notFound() public {
        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-2", a, PK1, "Bad", "nonexistent", _meta(PK1));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InitialRecordNotFound.selector, "rp1", "nonexistent")
        );
        index.createRecord("rp1", "cred-2", a, PK1, "Bad", "nonexistent", _meta(PK1));
    }

    function test_rotatedKey_initialMustBeOnSameRpId() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Initial on rp1");

        bytes32 a = _nextWalletRef();
        _commitOnly("rp2", "cred-2", a, PK2, "Bad rotation", "cred-1", _meta(PK2));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InitialRecordNotFound.selector, "rp2", "cred-1")
        );
        index.createRecord("rp2", "cred-2", a, PK2, "Bad rotation", "cred-1", _meta(PK2));
    }

    function test_revert_initialCredentialId_notRoot() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Initial");
        bytes32 a2 = _nextWalletRef();
        _commitOnly("rp1", "cred-2", a2, PK2, "Rotated", "cred-1", _meta(PK2));
        index.createRecord("rp1", "cred-2", a2, PK2, "Rotated", "cred-1", _meta(PK2));

        bytes32 a3 = _nextWalletRef();
        _commitOnly("rp1", "cred-3", a3, PK1, "Bad", "cred-2", _meta(PK1));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InitialRecordNotRoot.selector, "rp1", "cred-2")
        );
        index.createRecord("rp1", "cred-3", a3, PK1, "Bad", "cred-2", _meta(PK1));
    }

    // ── hasRecord / rpCount ──

    function test_hasRecord() public {
        assertFalse(index.hasRecord("rp1", "cred-1"));
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        assertTrue(index.hasRecord("rp1", "cred-1"));
        assertFalse(index.hasRecord("rp1", "cred-2"));
        assertFalse(index.hasRecord("rp2", "cred-1"));
    }

    function test_rpCount() public {
        assertEq(index.getTotalCredentialsByRpId("rp1"), 0);
        assertEq(index.getTotalCredentials(), 0);
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        assertEq(index.getTotalCredentials(), 1);
        _createInitialRecord("rp1", "cred-2", PK2, "Key 2");
        _createInitialRecord("rp2", "cred-3", PK1, "Key 3");
        assertEq(index.getTotalCredentialsByRpId("rp1"), 2);
        assertEq(index.getTotalCredentialsByRpId("rp2"), 1);
        assertEq(index.getTotalCredentialsByRpId("rp-none"), 0);
        assertEq(index.getTotalCredentials(), 3);
    }

    // ── Input Validation (single path) ──

    function test_revert_emptyRpId() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.EmptyRpId.selector);
        index.createRecord("", "cred-1", bytes32(uint256(99)), PK1, "bad", "cred-1", _meta(PK1));
    }

    function test_revert_emptyCredentialId() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.EmptyCredentialId.selector);
        index.createRecord("rp1", "", bytes32(uint256(99)), PK1, "bad", "", _meta(PK1));
    }

    function test_revert_publicKeyTooShort() public {
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyLength.selector, 32));
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), new bytes(32), "bad", "cred-1", _meta(PK1));
    }

    function test_revert_publicKeyTooLong() public {
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyLength.selector, 66));
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), new bytes(66), "bad", "cred-1", _meta(PK1));
    }

    function test_revert_publicKeyEmpty() public {
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyLength.selector, 0));
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), "", "bad", "cred-1", _meta(PK1));
    }

    function test_revert_rpIdTooLong() public {
        bytes memory longRpId = new bytes(254);
        for (uint256 i = 0; i < 254; i++) {
            longRpId[i] = "a";
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RpIdTooLong.selector, 254));
        index.createRecord(string(longRpId), "cred-1", bytes32(uint256(99)), PK1, "bad", "cred-1", _meta(PK1));
    }

    function test_revert_credentialIdTooLong() public {
        bytes memory longCredId = new bytes(1025);
        for (uint256 i = 0; i < 1025; i++) {
            longCredId[i] = "a";
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.CredentialIdTooLong.selector, 1025));
        index.createRecord("rp1", string(longCredId), bytes32(uint256(99)), PK1, "bad", string(longCredId), _meta(PK1));
    }

    function test_revert_nameTooLong() public {
        bytes memory longName = new bytes(257);
        for (uint256 i = 0; i < 257; i++) {
            longName[i] = "a";
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.NameTooLong.selector, 257));
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), PK1, string(longName), "cred-1", _meta(PK1));
    }

    function test_revert_publicKeyBadPrefix() public {
        bytes memory badPk = new bytes(65);
        badPk[0] = 0x03; // should be 0x04
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyPrefix.selector, bytes1(0x03))
        );
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), badPk, "bad", "cred-1", _meta(PK1));
    }

    function test_revert_publicKeyInvalidCoordinate() public {
        bytes memory badPk = abi.encodePacked(
            bytes1(0x04),
            bytes32(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff),
            bytes32(uint256(1))
        );
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyCoordinate.selector);
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), badPk, "bad", "cred-1", _meta(PK1));
    }

    function test_revert_publicKeyInvalidPoint() public {
        bytes memory badPk =
            hex"04aaa257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.InvalidPublicKeyPoint.selector);
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), badPk, "bad", "cred-1", _meta(PK1));
    }

    function test_revert_initialCredentialIdTooLong() public {
        bytes memory longInitCredId = new bytes(1025);
        for (uint256 i = 0; i < 1025; i++) {
            longInitCredId[i] = "a";
        }
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InitialCredentialIdTooLong.selector, 1025));
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), PK1, "bad", string(longInitCredId), _meta(PK1));
    }

    function test_maxLengthValues_succeed() public {
        bytes memory maxRpId = new bytes(253);
        for (uint256 i = 0; i < 253; i++) {
            maxRpId[i] = "a";
        }
        bytes memory maxCredId = new bytes(1024);
        for (uint256 i = 0; i < 1024; i++) {
            maxCredId[i] = "b";
        }
        bytes memory maxName = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            maxName[i] = "c";
        }

        bytes32 a = _nextWalletRef();
        _commitOnly(string(maxRpId), string(maxCredId), a, PK1, string(maxName), string(maxCredId), _meta(PK1));
        index.createRecord(string(maxRpId), string(maxCredId), a, PK1, string(maxName), string(maxCredId), _meta(PK1));
        assertTrue(index.hasRecord(string(maxRpId), string(maxCredId)));
    }

    // ── Event ──

    function test_emitsRecordCreated() public {
        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-1", a, PK1, "Key 1", "cred-1", _meta(PK1));
        bytes32 expectedKey = keccak256(abi.encode("rp1", "cred-1"));
        vm.expectEmit(true, true, true, true);
        emit WebAuthnP256PublicKeyIndexV3.RecordCreated(
            expectedKey, keccak256(bytes("rp1")), a, "rp1", "cred-1", PK1, "Key 1", "cred-1", _meta(PK1)
        );
        index.createRecord("rp1", "cred-1", a, PK1, "Key 1", "cred-1", _meta(PK1));
    }

    // ── Multiple callers ──

    function test_differentCallersCanCreate() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        bytes32 aAlice = _nextWalletRef();
        bytes32 aBob = _nextWalletRef();

        bytes32 cAlice = _commitment("rp1", "cred-a", aAlice, PK1, "Alice Key", "cred-a", _meta(PK1));
        bytes32 cBob = _commitment("rp1", "cred-b", aBob, PK2, "Bob Key", "cred-b", _meta(PK2));
        vm.prank(alice);
        index.commit(cAlice);
        vm.prank(bob);
        index.commit(cBob);

        vm.roll(block.number + 2);

        vm.prank(alice);
        index.createRecord("rp1", "cred-a", aAlice, PK1, "Alice Key", "cred-a", _meta(PK1));
        vm.prank(bob);
        index.createRecord("rp1", "cred-b", aBob, PK2, "Bob Key", "cred-b", _meta(PK2));

        assertEq(index.getRecord("rp1", "cred-a").publicKey, PK1);
        assertEq(index.getRecord("rp1", "cred-b").publicKey, PK2);
        assertEq(index.getTotalCredentialsByRpId("rp1"), 2);
    }

    // ── Commit-Reveal (single path) ──

    function test_revert_notCommitted() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.createRecord("rp1", "cred-1", bytes32(uint256(99)), PK1, "No commit", "cred-1", _meta(PK1));
    }

    function test_revert_revealTooEarly() public {
        bytes32 a = bytes32(uint256(99));
        index.commit(_commitment("rp1", "cred-1", a, PK1, "Early", "cred-1", _meta(PK1)));
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.RevealTooEarly.selector);
        index.createRecord("rp1", "cred-1", a, PK1, "Early", "cred-1", _meta(PK1));
    }

    function test_revealAtNextBlock_succeeds() public {
        bytes32 a = _nextWalletRef();
        index.commit(_commitment("rp1", "cred-1", a, PK1, "Next block", "cred-1", _meta(PK1)));
        vm.roll(block.number + index.REVEAL_DELAY());

        index.createRecord("rp1", "cred-1", a, PK1, "Next block", "cred-1", _meta(PK1));

        assertTrue(index.hasRecord("rp1", "cred-1"));
    }

    function test_commitClearedAfterReveal() public {
        bytes32 a = _nextWalletRef();
        bytes32 commitment = _commitment("rp1", "cred-1", a, PK1, "Clear", "cred-1", _meta(PK1));
        index.commit(commitment);
        assertEq(index.getCommitBlock(commitment), block.number);
        vm.roll(block.number + index.REVEAL_DELAY());

        index.createRecord("rp1", "cred-1", a, PK1, "Clear", "cred-1", _meta(PK1));

        assertEq(index.getCommitBlock(commitment), 0);
    }

    function test_revert_commitmentMismatch() public {
        bytes32 a = _nextWalletRef();
        index.commit(_commitment("rp1", "cred-1", a, PK1, "Expected", "cred-1", _meta(PK1)));
        vm.roll(block.number + index.REVEAL_DELAY());

        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.createRecord("rp1", "cred-1", a, PK1, "Changed", "cred-1", _meta(PK1));
    }

    function test_commitCanBeRevealedByDifferentCaller() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");
        bytes32 a = _nextWalletRef();
        bytes32 commitment = _commitment("rp1", "cred-1", a, PK1, "Alice", "cred-1", _meta(PK1));

        vm.prank(alice);
        index.commit(commitment);
        vm.roll(block.number + 2);

        vm.prank(bob);
        index.createRecord("rp1", "cred-1", a, PK1, "Alice", "cred-1", _meta(PK1));

        assertTrue(index.hasRecord("rp1", "cred-1"));
    }

    function test_commitOnlyStoredOnce() public {
        bytes32 a = _nextWalletRef();
        bytes32 commitment = _commitment("rp1", "cred-1", a, PK1, "Test", "cred-1", _meta(PK1));
        index.commit(commitment);
        uint256 committedAt = index.getCommitBlock(commitment);
        assertEq(committedAt, block.number);
        vm.roll(block.number + 5);
        index.commit(commitment); // should not overwrite
        assertEq(index.getCommitBlock(commitment), committedAt);
        vm.roll(block.number + 2);
        index.createRecord("rp1", "cred-1", a, PK1, "Test", "cred-1", _meta(PK1));
        assertTrue(index.hasRecord("rp1", "cred-1"));
    }

    // ── walletRef lookup ──

    function test_getRecordByWalletRef() public {
        bytes32 a = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "Key 1", a);

        WebAuthnP256PublicKeyIndexV3.PublicKeyRecord memory r = index.getRecordByWalletRef(a);
        assertEq(r.rpId, "rp1");
        assertEq(r.credentialId, "cred-1");
        assertEq(r.publicKey, PK1);
    }

    function test_revert_emptyWalletRef() public {
        bytes32 a = bytes32(0);
        _commitOnly("rp1", "cred-1", a, PK1, "Key 1", "cred-1", _meta(PK1));
        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.EmptyWalletRef.selector);
        index.createRecord("rp1", "cred-1", a, PK1, "Key 1", "cred-1", _meta(PK1));
    }

    function test_getRecordByWalletRef_notFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefNotFound.selector, bytes32(uint256(999)))
        );
        index.getRecordByWalletRef(bytes32(uint256(999)));
    }

    // ── getCommitBlock ──

    function test_getCommitBlock() public {
        bytes32 c = keccak256("test");
        assertEq(index.getCommitBlock(c), 0);
        index.commit(c);
        assertEq(index.getCommitBlock(c), block.number);
    }

    // ── Enumeration: getTotalRpIds / getRpIds ──

    function test_getTotalRpIds() public {
        assertEq(index.getTotalRpIds(), 0);
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        assertEq(index.getTotalRpIds(), 1);
        _createInitialRecord("rp1", "cred-2", PK2, "K2");
        assertEq(index.getTotalRpIds(), 1); // same rpId, no increase
        _createInitialRecord("rp2", "cred-3", PK1, "K3");
        assertEq(index.getTotalRpIds(), 2);
    }

    function test_getRpIds_asc() public {
        vm.warp(1000);
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        vm.warp(2000);
        _createInitialRecord("rp2", "cred-2", PK2, "K2");

        (uint256 total, string[] memory rpIds, uint256[] memory counts, uint256[] memory createdAts) =
            index.getRpIds(0, 10, false);
        assertEq(total, 2);
        assertEq(rpIds.length, 2);
        assertEq(rpIds[0], "rp1");
        assertEq(rpIds[1], "rp2");
        assertEq(counts[0], 1);
        assertEq(counts[1], 1);
        assertEq(createdAts[0], 1000);
        assertEq(createdAts[1], 2000);
    }

    function test_getRpIds_desc() public {
        vm.warp(1000);
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        vm.warp(2000);
        _createInitialRecord("rp2", "cred-2", PK2, "K2");

        (uint256 total, string[] memory rpIds,,) = index.getRpIds(0, 10, true);
        assertEq(total, 2);
        assertEq(rpIds[0], "rp2");
        assertEq(rpIds[1], "rp1");
    }

    function test_getRpIds_pagination() public {
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        _createInitialRecord("rp2", "cred-2", PK2, "K2");
        _createInitialRecord("rp3", "cred-3", PK1, "K3");

        (uint256 total, string[] memory page1,,) = index.getRpIds(0, 2, false);
        assertEq(total, 3);
        assertEq(page1.length, 2);
        assertEq(page1[0], "rp1");
        assertEq(page1[1], "rp2");

        (, string[] memory page2,,) = index.getRpIds(2, 2, false);
        assertEq(page2.length, 1);
        assertEq(page2[0], "rp3");
    }

    function test_getRpIds_offsetBeyondTotal() public {
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        (uint256 total, string[] memory rpIds,,) = index.getRpIds(100, 10, false);
        assertEq(total, 1);
        assertEq(rpIds.length, 0);
    }

    // ── Enumeration: getKeysByRpId ──

    function test_getKeysByRpId_asc() public {
        vm.warp(1000);
        _createInitialRecord("rp1", "cred-a", PK1, "A");
        vm.warp(2000);
        bytes32 a = _nextWalletRef();
        _commitOnly("rp1", "cred-b", a, PK2, "B", "cred-a", _meta(PK2));
        index.createRecord("rp1", "cred-b", a, PK2, "B", "cred-a", _meta(PK2));

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getKeysByRpId("rp1", 0, 10, false);
        assertEq(total, 2);
        assertEq(records[0].credentialId, "cred-a");
        assertEq(records[1].credentialId, "cred-b");
        assertEq(records[0].createdAt, 1000);
        assertEq(records[1].createdAt, 2000);
    }

    function test_getKeysByRpId_desc() public {
        _createInitialRecord("rp1", "cred-a", PK1, "A");
        _createInitialRecord("rp1", "cred-b", PK2, "B");

        (, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) = index.getKeysByRpId("rp1", 0, 10, true);
        assertEq(records[0].credentialId, "cred-b");
        assertEq(records[1].credentialId, "cred-a");
    }

    function test_getKeysByRpId_includesWalletMembers() public {
        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members2("cred-1", "cred-2"));

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getKeysByRpId("rp1", 0, 10, false);
        assertEq(total, 2);
        assertEq(records[0].credentialId, "cred-1");
        assertEq(records[1].credentialId, "cred-2");
    }

    function test_getKeysByRpId_pagination() public {
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        _createInitialRecord("rp1", "cred-2", PK2, "K2");

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory page1) =
            index.getKeysByRpId("rp1", 0, 1, false);
        assertEq(total, 2);
        assertEq(page1.length, 1);
        assertEq(page1[0].credentialId, "cred-1");

        (, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory page2) = index.getKeysByRpId("rp1", 1, 1, false);
        assertEq(page2.length, 1);
        assertEq(page2[0].credentialId, "cred-2");
    }

    function test_getKeysByRpId_emptyRpId() public view {
        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getKeysByRpId("nonexistent", 0, 10, false);
        assertEq(total, 0);
        assertEq(records.length, 0);
    }

    function test_getKeysByRpId_offsetBeyondTotal() public {
        _createInitialRecord("rp1", "cred-1", PK1, "K1");
        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getKeysByRpId("rp1", 100, 10, false);
        assertEq(total, 1);
        assertEq(records.length, 0);
    }

    // ── Native batch (single-key records) ──

    function test_nativeBatch_singleKeyRecords() public {
        bytes32 w1 = bytes32(uint256(0x1234));
        bytes32 w2 = bytes32(uint256(0x5678));

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = _commitment("rp1", "cred-1", w1, PK1, "K1", "cred-1", _meta(PK1));
        commitments[1] = _commitment("rp1", "cred-2", w2, PK2, "K2", "cred-2", _meta(PK2));
        index.batchCommit(commitments);
        vm.roll(block.number + 2);

        WebAuthnP256PublicKeyIndexV3.CreateParams[] memory params = new WebAuthnP256PublicKeyIndexV3.CreateParams[](2);
        params[0] = WebAuthnP256PublicKeyIndexV3.CreateParams("rp1", "cred-1", w1, PK1, "K1", "cred-1", _meta(PK1));
        params[1] = WebAuthnP256PublicKeyIndexV3.CreateParams("rp1", "cred-2", w2, PK2, "K2", "cred-2", _meta(PK2));
        index.batchCreateRecord(params);

        assertEq(index.getTotalCredentials(), 2);
        assertEq(index.getTotalWallets(), 2);
    }

    function test_nativeBatch_partialFailure_reverts() public {
        // Only the first record is committed; the whole batch must revert.
        bytes32 w1 = bytes32(uint256(0x1234));
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = _commitment("rp1", "cred-1", w1, PK1, "K1", "cred-1", _meta(PK1));
        index.batchCommit(commitments);
        vm.roll(block.number + 2);

        WebAuthnP256PublicKeyIndexV3.CreateParams[] memory params = new WebAuthnP256PublicKeyIndexV3.CreateParams[](2);
        params[0] = WebAuthnP256PublicKeyIndexV3.CreateParams("rp1", "cred-1", w1, PK1, "K1", "cred-1", _meta(PK1));
        params[1] = WebAuthnP256PublicKeyIndexV3.CreateParams(
            "rp2", "cred-2", bytes32(uint256(0x9999)), PK2, "K2", "cred-2", _meta(PK2)
        );

        vm.expectRevert(WebAuthnP256PublicKeyIndexV3.NotCommitted.selector);
        index.batchCreateRecord(params);

        assertFalse(index.hasRecord("rp1", "cred-1"));
        assertFalse(index.hasRecord("rp2", "cred-2"));
    }

    // ── V2 fallback ──

    function _etchV2() internal returns (WebAuthnP256PublicKeyIndex v2) {
        WebAuthnP256PublicKeyIndex impl = new WebAuthnP256PublicKeyIndex();
        vm.etch(index.V2_ADDRESS(), address(impl).code);
        return WebAuthnP256PublicKeyIndex(index.V2_ADDRESS());
    }

    function _seedV2(
        WebAuthnP256PublicKeyIndex v2,
        string memory rpId,
        string memory credentialId,
        bytes memory pk,
        string memory name,
        bytes32 walletRef
    ) internal {
        // V2 production records carry the old abi.encode metadata convention.
        v2.commit(_commitment(rpId, credentialId, walletRef, pk, name, credentialId, _legacyMeta(pk)));
        vm.roll(block.number + 2);
        v2.createRecord(rpId, credentialId, walletRef, pk, name, credentialId, _legacyMeta(pk));
    }

    function test_v2Fallback_getRecord() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", bytes32(uint256(0xBEEF)));

        WebAuthnP256PublicKeyIndexV3.PublicKeyRecord memory r = index.getRecord("rp1", "cred-old");
        assertEq(r.credentialId, "cred-old");
        assertEq(r.publicKey, PK1);
        assertEq(r.walletRef, bytes32(uint256(0xBEEF)));
        assertEq(r.name, "Legacy");
        // V2's abi.encode metadata is discarded; V3 rebuilds the packed convention from the pubkey
        assertEq(r.metadata, _meta(PK1));
        assertTrue(index.hasRecord("rp1", "cred-old"));
    }

    function test_v2Fallback_getRecord_missingInBoth_reverts() public {
        _etchV2();
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordNotFound.selector, "rp1", "nope"));
        index.getRecord("rp1", "nope");
    }

    function test_v2Fallback_v3RecordWins() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-v2only", PK1, "Legacy", bytes32(uint256(0xBEEF)));
        _createInitialRecord("rp1", "cred-v3", PK2, "Native");

        assertEq(index.getRecord("rp1", "cred-v3").publicKey, PK2);
        assertEq(index.getRecord("rp1", "cred-v2only").publicKey, PK1);
    }

    function test_v2Fallback_walletRefLookups() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        bytes32 w = bytes32(uint256(0xBEEF));
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", w);

        assertEq(index.getRecordByWalletRef(w).credentialId, "cred-old");
        assertEq(index.getTotalCredentialsByWalletRef(w), 1);

        (uint256 total, WebAuthnP256PublicKeyIndexV3.PublicKeyRecord[] memory records) =
            index.getRecordsByWalletRef(w, 0, 10, false);
        assertEq(total, 1);
        assertEq(records.length, 1);
        assertEq(records[0].credentialId, "cred-old");
        assertEq(records[0].metadata, _meta(PK1)); // normalized to the packed convention

        // offset beyond the single V2 record still reports total = 1
        (total, records) = index.getRecordsByWalletRef(w, 1, 10, false);
        assertEq(total, 1);
        assertEq(records.length, 0);
    }

    function test_v2Fallback_walletRefMissingInBoth_reverts() public {
        _etchV2();
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefNotFound.selector, bytes32(uint256(777)))
        );
        index.getRecordByWalletRef(bytes32(uint256(777)));
    }

    function test_v2Fallback_hasRecord_falseWhenMissingInBoth() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", bytes32(uint256(0xBEEF)));
        assertFalse(index.hasRecord("rp1", "nope"));
        assertFalse(index.hasRecord("rp2", "cred-old"));
    }

    function test_v2Fallback_getTotalCredentialsByWalletRef_unknownRef() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", bytes32(uint256(0xBEEF)));
        assertEq(index.getTotalCredentialsByWalletRef(bytes32(uint256(777))), 0);
    }

    function test_v2Fallback_unexpectedRevertBubbles_failClosed() public {
        // If the code at V2_ADDRESS reverts with anything other than the
        // expected errors, V3 must not reinterpret that as "absent".
        RevertingV2Mock mock = new RevertingV2Mock();
        vm.etch(index.V2_ADDRESS(), address(mock).code);

        vm.expectRevert(RevertingV2Mock.Unexpected.selector);
        index.getTotalCredentialsByWalletRef(bytes32(uint256(1)));

        vm.expectRevert(RevertingV2Mock.Unexpected.selector);
        index.getRecordsByWalletRef(bytes32(uint256(1)), 0, 10, false);
    }

    function test_v2Fallback_createRecord_rejectsV2Credential() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", bytes32(uint256(0xBEEF)));

        bytes32 w = _nextWalletRef();
        _commitOnly("rp1", "cred-old", w, PK2, "Shadow", "cred-old", _meta(PK2));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordAlreadyExists.selector, "rp1", "cred-old")
        );
        index.createRecord("rp1", "cred-old", w, PK2, "Shadow", "cred-old", _meta(PK2));
    }

    function test_v2Fallback_createRecord_rejectsV2WalletRef() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        bytes32 w = bytes32(uint256(0xBEEF));
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", w);

        _commitOnly("rp1", "cred-new", w, PK2, "Shadow", "cred-new", _meta(PK2));
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefAlreadyExists.selector, w));
        index.createRecord("rp1", "cred-new", w, PK2, "Shadow", "cred-new", _meta(PK2));
    }

    function test_v2Fallback_createWallet_rejectsV2WalletRef() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        bytes32 w = bytes32(uint256(0xBEEF));
        _seedV2(v2, "rp1", "cred-old", PK1, "Legacy", w);

        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");
        index.commit(_walletCommitment("rp1", w, members));
        vm.roll(block.number + 2);
        vm.expectRevert(abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.WalletRefAlreadyExists.selector, w));
        index.createWallet("rp1", w, members);
    }

    function test_v2Fallback_createWallet_rejectsV2Credential() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-2", PK2, "Legacy", bytes32(uint256(0xBEEF)));

        bytes32 w = _nextWalletRef();
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members2("cred-1", "cred-2");
        index.commit(_walletCommitment("rp1", w, members));
        vm.roll(block.number + 2);
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.RecordAlreadyExists.selector, "rp1", "cred-2")
        );
        index.createWallet("rp1", w, members);
        assertFalse(index.hasRecord("rp1", "cred-1")); // atomic: first member rolled back
    }

    function test_v2Fallback_statsAreV3Only() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-v2a", PK1, "L1", bytes32(uint256(0xB1)));
        _seedV2(v2, "rp1", "cred-v2b", PK2, "L2", bytes32(uint256(0xB2)));

        bytes32 w = _nextWalletRef();
        _createWallet(w, "rp1", _members2("cred-1", "cred-2"));

        // V2 history stays readable through the fallback but is excluded from V3 stats.
        assertEq(index.getTotalCredentials(), 2);
        assertEq(index.getTotalWallets(), 1);
        assertEq(v2.getTotalCredentials(), 2); // V2 keeps its own count for off-chain addition
    }

    function test_v2WrittenAfterV3_readsPreferV3_statsUnaffected() public {
        // V2 stays permissionless after V3 goes live and knows nothing about V3, so a
        // direct V2 write can duplicate a V3 credential or walletRef. Reads prefer V3,
        // and since stats are V3-only, the counters cannot be inflated from V2 either.
        WebAuthnP256PublicKeyIndex v2 = _etchV2();

        bytes32 w = _nextWalletRef();
        _createRecordWithRef("rp1", "cred-1", PK1, "Native", w);
        assertEq(index.getTotalCredentials(), 1);
        assertEq(index.getTotalWallets(), 1);

        // Same (rpId, credentialId) AND same walletRef written straight into V2.
        _seedV2(v2, "rp1", "cred-1", PK2, "Shadow", w);

        // Reads still resolve to the V3 record; the V2 duplicate is invisible.
        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
        assertEq(index.getRecordByWalletRef(w).publicKey, PK1);
        (uint256 total,) = index.getRecordsByWalletRef(w, 0, 10, false);
        assertEq(total, 1);

        // V3-only counters are untouched by the direct V2 write.
        assertEq(index.getTotalCredentials(), 1);
        assertEq(index.getTotalWallets(), 1);
    }

    function test_v2Fallback_rotation_rootInV2() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-root", PK1, "Root", bytes32(uint256(0xB1)));

        bytes32 w = _nextWalletRef();
        _commitOnly("rp1", "cred-rot", w, PK2, "Rotated", "cred-root", _meta(PK2));
        index.createRecord("rp1", "cred-rot", w, PK2, "Rotated", "cred-root", _meta(PK2));
        assertEq(index.getRecord("rp1", "cred-rot").initialCredentialId, "cred-root");
    }

    function test_v2Fallback_rotation_v2RecordNotRoot_reverts() public {
        WebAuthnP256PublicKeyIndex v2 = _etchV2();
        _seedV2(v2, "rp1", "cred-root", PK1, "Root", bytes32(uint256(0xB1)));
        // A rotated (non-root) record in V2, with its own walletRef (V2 enforces one-to-one)
        v2.commit(_commitment("rp1", "cred-mid", bytes32(uint256(0xB2)), PK2, "Mid", "cred-root", _legacyMeta(PK2)));
        vm.roll(block.number + 2);
        v2.createRecord("rp1", "cred-mid", bytes32(uint256(0xB2)), PK2, "Mid", "cred-root", _legacyMeta(PK2));

        bytes32 w = _nextWalletRef();
        _commitOnly("rp1", "cred-bad", w, PK3, "Bad", "cred-mid", _meta(PK3));
        vm.expectRevert(
            abi.encodeWithSelector(WebAuthnP256PublicKeyIndexV3.InitialRecordNotRoot.selector, "rp1", "cred-mid")
        );
        index.createRecord("rp1", "cred-bad", w, PK3, "Bad", "cred-mid", _meta(PK3));
    }
}
