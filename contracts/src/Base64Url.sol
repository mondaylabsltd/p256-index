// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal base64url (RFC 4648 §5, no padding) encoder for 32-byte
///         values — exactly what a WebAuthn clientDataJSON challenge carries.
library Base64Url {
    bytes internal constant ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// @dev Encodes 32 bytes into the 43-character unpadded base64url string.
    function encode32(bytes32 value) internal pure returns (string memory) {
        bytes memory out = new bytes(43);
        uint256 outIndex = 0;
        // Process 30 bytes as ten 3-byte groups, then the trailing 2 bytes.
        for (uint256 i = 0; i < 30; i += 3) {
            uint256 chunk =
                (uint256(uint8(value[i])) << 16) | (uint256(uint8(value[i + 1])) << 8) | uint256(uint8(value[i + 2]));
            out[outIndex++] = ALPHABET[(chunk >> 18) & 0x3f];
            out[outIndex++] = ALPHABET[(chunk >> 12) & 0x3f];
            out[outIndex++] = ALPHABET[(chunk >> 6) & 0x3f];
            out[outIndex++] = ALPHABET[chunk & 0x3f];
        }
        uint256 tail = (uint256(uint8(value[30])) << 8) | uint256(uint8(value[31]));
        out[outIndex++] = ALPHABET[(tail >> 10) & 0x3f];
        out[outIndex++] = ALPHABET[(tail >> 4) & 0x3f];
        out[outIndex] = ALPHABET[(tail << 2) & 0x3f];
        return string(out);
    }
}
