// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";
import {WebAuthnP256BatchHelper} from "../src/WebAuthnP256BatchHelper.sol";

contract WebAuthnP256BatchHelperTest is Test {
    WebAuthnP256PublicKeyIndex public index;
    WebAuthnP256BatchHelper public batch;

    bytes constant PK1 =
        hex"045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
    bytes constant PK2 =
        hex"04550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e24136093d7012e509a73715cbd0b00a3cc0ff4b5c01b3ffa196ab1fb327036b8e6";
    bytes constant PK3 =
        hex"04dff13c9668fd5ddc5022e9eb6f04be68a5ded7e40a61a84e35ee26ec675f995b20f1f64466711963e4f758bf5abaf12f569716cdc146a1c0cc8990d41d2f92fb";

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndex();
        batch = new WebAuthnP256BatchHelper();
    }

    function _commitment(
        string memory rpId, string memory credentialId, bytes32 walletRef,
        bytes memory pk, string memory name, string memory initCredId, bytes memory metadata
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(rpId, credentialId, walletRef, pk, name, initCredId, metadata));
    }

    function test_batchCommitAndCreate() public {
        bytes32 w1 = bytes32(uint256(1));
        bytes32 w2 = bytes32(uint256(2));
        bytes32 w3 = bytes32(uint256(3));

        bytes32[] memory commitments = new bytes32[](3);
        commitments[0] = _commitment("rp1", "cred-1", w1, PK1, "K1", "cred-1", "");
        commitments[1] = _commitment("rp1", "cred-2", w2, PK2, "K2", "cred-2", "");
        commitments[2] = _commitment("rp2", "cred-3", w3, PK3, "K3", "cred-3", "");

        // Batch commit — 1 transaction for 3 commits
        batch.batchCommit(index, commitments);
        vm.roll(block.number + 2);

        // Batch create — 1 transaction for 3 records
        WebAuthnP256BatchHelper.CreateParams[] memory params = new WebAuthnP256BatchHelper.CreateParams[](3);
        params[0] = WebAuthnP256BatchHelper.CreateParams("rp1", "cred-1", w1, PK1, "K1", "cred-1", "");
        params[1] = WebAuthnP256BatchHelper.CreateParams("rp1", "cred-2", w2, PK2, "K2", "cred-2", "");
        params[2] = WebAuthnP256BatchHelper.CreateParams("rp2", "cred-3", w3, PK3, "K3", "cred-3", "");
        batch.batchCreateRecord(index, params);

        // Verify all 3 records
        assertTrue(index.hasRecord("rp1", "cred-1"));
        assertTrue(index.hasRecord("rp1", "cred-2"));
        assertTrue(index.hasRecord("rp2", "cred-3"));
        assertEq(index.getTotalCredentials(), 3);
        assertEq(index.getTotalCredentialsByRpId("rp1"), 2);
        assertEq(index.getTotalCredentialsByRpId("rp2"), 1);

        // Verify walletRef lookup
        assertEq(index.getRecordByWalletRef(w1).credentialId, "cred-1");
        assertEq(index.getRecordByWalletRef(w2).credentialId, "cred-2");
        assertEq(index.getRecordByWalletRef(w3).credentialId, "cred-3");
    }

    function test_batchPartialFailure_reverts() public {
        bytes32 w1 = bytes32(uint256(1));
        bytes32 w2 = bytes32(uint256(2));

        // Only commit first record
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = _commitment("rp1", "cred-1", w1, PK1, "K1", "cred-1", "");
        batch.batchCommit(index, commitments);
        vm.roll(block.number + 2);

        // Try to batch create 2 records — second has no commit, entire batch reverts
        WebAuthnP256BatchHelper.CreateParams[] memory params = new WebAuthnP256BatchHelper.CreateParams[](2);
        params[0] = WebAuthnP256BatchHelper.CreateParams("rp1", "cred-1", w1, PK1, "K1", "cred-1", "");
        params[1] = WebAuthnP256BatchHelper.CreateParams("rp1", "cred-2", w2, PK2, "K2", "cred-2", "");

        vm.expectRevert(WebAuthnP256PublicKeyIndex.NotCommitted.selector);
        batch.batchCreateRecord(index, params);

        // Nothing was created (atomic)
        assertFalse(index.hasRecord("rp1", "cred-1"));
        assertFalse(index.hasRecord("rp1", "cred-2"));
    }

    function test_batchEmpty() public {
        // Empty arrays should not revert
        bytes32[] memory empty = new bytes32[](0);
        batch.batchCommit(index, empty);

        WebAuthnP256BatchHelper.CreateParams[] memory emptyParams = new WebAuthnP256BatchHelper.CreateParams[](0);
        batch.batchCreateRecord(index, emptyParams);
    }
}
