// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndexV3} from "../src/WebAuthnP256PublicKeyIndexV3.sol";

/// Gas profile for createWallet at various member counts. Run with:
///   forge test --match-contract GasProfileTest -vv
contract GasProfileTest is Test {
    WebAuthnP256PublicKeyIndexV3 public index;

    bytes constant PK1 =
        hex"045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";

    uint256 private _blockCursor = 1;

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndexV3();
    }

    /// via_ir may legally cache block.number reads within one call frame, so
    /// the cursor is tracked explicitly instead of read back from the env.
    function _advanceBlocks() internal {
        _blockCursor += 2;
        vm.roll(_blockCursor);
    }

    function _members(uint256 n, uint256 salt)
        internal
        pure
        returns (WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members)
    {
        members = new WebAuthnP256PublicKeyIndexV3.WalletMember[](n);
        for (uint256 i = 0; i < n; i++) {
            members[i] = WebAuthnP256PublicKeyIndexV3.WalletMember(
                string(abi.encodePacked("credential-", vm.toString(salt), "-", vm.toString(i))),
                PK1,
                "My Passkey Device"
            );
        }
    }

    function _measureWallet(uint256 n) internal returns (uint256 execGas, uint256 calldataBytes) {
        bytes32 w = bytes32(uint256(0xA000 + n));
        WebAuthnP256PublicKeyIndexV3.WalletMember[] memory members = _members(n, n);
        index.commit(keccak256(abi.encode(index.WALLET_COMMIT_TAG(), "wallet.example.com", w, members)));
        _advanceBlocks();

        bytes memory callData =
            abi.encodeCall(WebAuthnP256PublicKeyIndexV3.createWallet, ("wallet.example.com", w, members));
        calldataBytes = callData.length;

        uint256 before = gasleft();
        index.createWallet("wallet.example.com", w, members);
        execGas = before - gasleft();
    }

    function test_gasProfile_createWallet() public {
        // Reference: a single-key createRecord.
        bytes32 wSingle = bytes32(uint256(0x5157));
        bytes memory meta = abi.encodePacked(bytes32("VelaWalletV1"), PK1);
        index.commit(
            keccak256(
                abi.encode("wallet.example.com", "cred-single", wSingle, PK1, "My Passkey Device", "cred-single", meta)
            )
        );
        _advanceBlocks();
        uint256 before = gasleft();
        index.createRecord("wallet.example.com", "cred-single", wSingle, PK1, "My Passkey Device", "cred-single", meta);
        console2.log("createRecord (single) exec gas:", before - gasleft());

        uint256[8] memory sizes = [uint256(1), 2, 3, 5, 7, 8, 13, 21];
        for (uint256 i = 0; i < sizes.length; i++) {
            (uint256 execGas, uint256 calldataBytes) = _measureWallet(sizes[i]);
            // Full tx cost ~= 21_000 intrinsic + ~16/byte calldata + exec.
            uint256 txEstimate = 21_000 + calldataBytes * 16 + execGas;
            console2.log("members:", sizes[i]);
            console2.log("  exec gas:", execGas);
            console2.log("  approx full tx gas:", txEstimate);
        }
    }
}
