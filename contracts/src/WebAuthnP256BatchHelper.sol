// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {WebAuthnP256PublicKeyIndex} from "./WebAuthnP256PublicKeyIndex.sol";

/// @title WebAuthnP256BatchHelper
/// @author Built by Vela Wallet (https://getvela.app)
/// @notice Stateless helper for batching commit and createRecord calls.
///         Reduces N commits + N creates from 2N transactions to 2.
contract WebAuthnP256BatchHelper {
    struct CreateParams {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
    }

    /// @notice Batch commit multiple commitments in one transaction.
    function batchCommit(WebAuthnP256PublicKeyIndex index, bytes32[] calldata commitments) external {
        for (uint256 i = 0; i < commitments.length; i++) {
            index.commit(commitments[i]);
        }
    }

    /// @notice Batch create multiple records in one transaction.
    function batchCreateRecord(WebAuthnP256PublicKeyIndex index, CreateParams[] calldata params) external {
        for (uint256 i = 0; i < params.length; i++) {
            index.createRecord(
                params[i].rpId,
                params[i].credentialId,
                params[i].walletRef,
                params[i].publicKey,
                params[i].name,
                params[i].initialCredentialId,
                params[i].metadata
            );
        }
    }
}
