// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title WebAuthnP256PublicKeyIndex
/// @author Built by Vela Wallet (https://getvela.app)
/// @notice Stores WebAuthn P256 passkey public keys on-chain.
///         Single source of truth for all chains. Records are append-only.
///         (rpId, credentialId) is globally unique — first come, first served.
contract WebAuthnP256PublicKeyIndex {
    uint8 public constant VERSION = 2;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant MAX_CREDENTIAL_ID_LENGTH = 1024;
    uint256 public constant MAX_NAME_LENGTH = 256;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)
    uint256 public constant MAX_METADATA_LENGTH = 1024;
    uint256 public constant REVEAL_DELAY = 1;

    uint256 private constant _P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 private constant _P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    struct PublicKeyRecord {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
        uint256 createdAt;
    }

    mapping(bytes32 => PublicKeyRecord) private _records;
    mapping(bytes32 => uint256) private _commitBlockPlusOne;

    // Enumeration support
    uint256 private _totalCredentials;
    string[] private _rpIds;
    mapping(string => uint256) private _rpCreatedAt;
    mapping(string => string[]) private _rpCredentials;
    mapping(bytes32 => bytes32) private _recordKeyByWalletRef;

    event RecordCreated(
        bytes32 indexed key,
        bytes32 indexed rpIdHash,
        bytes32 indexed walletRef,
        string rpId,
        string credentialId,
        bytes publicKey,
        string name,
        string initialCredentialId,
        bytes metadata
    );

    error EmptyRpId();
    error EmptyCredentialId();
    error InvalidPublicKeyLength(uint256 length);
    error RpIdTooLong(uint256 length);
    error CredentialIdTooLong(uint256 length);
    error NameTooLong(uint256 length);
    error RecordAlreadyExists(string rpId, string credentialId);
    error RecordNotFound(string rpId, string credentialId);
    error InvalidPublicKeyPrefix(bytes1 prefix);
    error InitialCredentialIdTooLong(uint256 length);
    error MetadataTooLong(uint256 length);
    error InitialRecordNotFound(string rpId, string initialCredentialId);
    error InitialRecordNotRoot(string rpId, string initialCredentialId);
    error NotCommitted();
    error RevealTooEarly();
    error EmptyWalletRef();
    error WalletRefNotFound(bytes32 walletRef);
    error WalletRefAlreadyExists(bytes32 walletRef);
    error InvalidPublicKeyCoordinate();
    error InvalidPublicKeyPoint();

    function _recordKey(string calldata rpId, string calldata credentialId) internal pure returns (bytes32) {
        return keccak256(abi.encode(rpId, credentialId));
    }

    function _recordExists(bytes32 key) internal view returns (bool) {
        return bytes(_records[key].rpId).length != 0;
    }

    function _validatePublicKey(bytes calldata publicKey) internal pure {
        if (publicKey.length != UNCOMPRESSED_P256_KEY_LENGTH) {
            revert InvalidPublicKeyLength(publicKey.length);
        }
        if (publicKey[0] != 0x04) revert InvalidPublicKeyPrefix(publicKey[0]);

        uint256 x = uint256(bytes32(publicKey[1:33]));
        uint256 y = uint256(bytes32(publicKey[33:65]));

        if (x >= _P256_P || y >= _P256_P) revert InvalidPublicKeyCoordinate();

        uint256 lhs = mulmod(y, y, _P256_P);
        uint256 x2 = mulmod(x, x, _P256_P);
        uint256 x3 = mulmod(x2, x, _P256_P);
        uint256 rhs = addmod(addmod(x3, mulmod(_P256_P - 3, x, _P256_P), _P256_P), _P256_B, _P256_P);
        if (lhs != rhs) revert InvalidPublicKeyPoint();
    }

    // ── Write ──

    /// @notice Commit a future record registration. Must be called before createRecord.
    /// @param commitment keccak256(abi.encode(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata))
    function commit(bytes32 commitment) external {
        if (_commitBlockPlusOne[commitment] == 0) {
            _commitBlockPlusOne[commitment] = block.number + 1;
        }
    }

    /// @notice Check if a commitment exists and return the block number it was committed at (0 = not committed).
    function getCommitBlock(bytes32 commitment) external view returns (uint256) {
        uint256 v = _commitBlockPlusOne[commitment];
        return v == 0 ? 0 : v - 1;
    }

    /// @notice Store a new passkey public key record. Requires a prior commit.
    /// @param initialCredentialId Must equal credentialId (initial key) or reference an existing record (rotated key).
    /// @param walletRef Cross-chain wallet address identifier (bytes32). For EVM addresses: bytes32(uint256(uint160(addr))). For 32-byte addresses (Solana/Aptos): use directly. For >32 bytes: use keccak256.
    function createRecord(
        string calldata rpId,
        string calldata credentialId,
        bytes32 walletRef,
        bytes calldata publicKey,
        string calldata name,
        string calldata initialCredentialId,
        bytes calldata metadata
    ) external {
        if (bytes(rpId).length == 0) revert EmptyRpId();
        if (bytes(rpId).length > MAX_RPID_LENGTH) {
            revert RpIdTooLong(bytes(rpId).length);
        }
        if (bytes(credentialId).length == 0) revert EmptyCredentialId();
        if (bytes(credentialId).length > MAX_CREDENTIAL_ID_LENGTH) {
            revert CredentialIdTooLong(bytes(credentialId).length);
        }
        _validatePublicKey(publicKey);
        if (bytes(name).length > MAX_NAME_LENGTH) {
            revert NameTooLong(bytes(name).length);
        }
        if (bytes(initialCredentialId).length > MAX_CREDENTIAL_ID_LENGTH) {
            revert InitialCredentialIdTooLong(bytes(initialCredentialId).length);
        }
        if (metadata.length > MAX_METADATA_LENGTH) {
            revert MetadataTooLong(metadata.length);
        }
        if (walletRef == bytes32(0)) revert EmptyWalletRef();
        if (_recordKeyByWalletRef[walletRef] != bytes32(0)) {
            revert WalletRefAlreadyExists(walletRef);
        }

        // Verify commit-reveal
        bytes32 commitment =
            keccak256(abi.encode(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata));
        uint256 commitBlockPlusOne = _commitBlockPlusOne[commitment];
        if (commitBlockPlusOne == 0) revert NotCommitted();
        if (block.number < (commitBlockPlusOne - 1) + REVEAL_DELAY) {
            revert RevealTooEarly();
        }
        delete _commitBlockPlusOne[commitment];

        bytes32 k = _recordKey(rpId, credentialId);
        if (_recordExists(k)) {
            revert RecordAlreadyExists(rpId, credentialId);
        }

        // initialCredentialId must equal credentialId (initial key) or reference an existing root record
        if (keccak256(bytes(initialCredentialId)) != keccak256(bytes(credentialId))) {
            bytes32 initKey = _recordKey(rpId, initialCredentialId);
            if (!_recordExists(initKey)) {
                revert InitialRecordNotFound(rpId, initialCredentialId);
            }
            if (keccak256(bytes(_records[initKey].initialCredentialId)) != keccak256(bytes(initialCredentialId))) {
                revert InitialRecordNotRoot(rpId, initialCredentialId);
            }
        }

        _records[k] = PublicKeyRecord({
            rpId: rpId,
            credentialId: credentialId,
            walletRef: walletRef,
            publicKey: publicKey,
            name: name,
            initialCredentialId: initialCredentialId,
            metadata: metadata,
            createdAt: block.timestamp
        });
        if (_rpCredentials[rpId].length == 0) {
            _rpIds.push(rpId);
            _rpCreatedAt[rpId] = block.timestamp;
        }
        _rpCredentials[rpId].push(credentialId);
        _recordKeyByWalletRef[walletRef] = k;
        _totalCredentials++;

        emit RecordCreated(
            k, keccak256(bytes(rpId)), walletRef, rpId, credentialId, publicKey, name, initialCredentialId, metadata
        );
    }

    // ── Read ──

    /// @notice Query a record by rpId and credentialId.
    function getRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (PublicKeyRecord memory)
    {
        bytes32 k = _recordKey(rpId, credentialId);
        if (!_recordExists(k)) {
            revert RecordNotFound(rpId, credentialId);
        }
        return _records[k];
    }

    /// @notice Query a record by walletRef (cross-chain wallet address).
    function getRecordByWalletRef(bytes32 walletRef) external view returns (PublicKeyRecord memory) {
        bytes32 k = _recordKeyByWalletRef[walletRef];
        if (k == bytes32(0)) revert WalletRefNotFound(walletRef);
        return _records[k];
    }

    /// @notice Check if a record exists.
    function hasRecord(string calldata rpId, string calldata credentialId) external view returns (bool) {
        return _recordExists(_recordKey(rpId, credentialId));
    }

    /// @notice Get the number of credentials registered under an rpId.
    function getTotalCredentialsByRpId(string calldata rpId) external view returns (uint256) {
        return _rpCredentials[rpId].length;
    }

    /// @notice Total number of credentials across all rpIds.
    function getTotalCredentials() external view returns (uint256) {
        return _totalCredentials;
    }

    /// @notice Total number of distinct rpIds.
    function getTotalRpIds() external view returns (uint256) {
        return _rpIds.length;
    }

    /// @notice Paginated list of all rpIds with counts and creation times.
    /// @param offset Number of items to skip.
    /// @param limit  Max items to return.
    /// @param desc   true = newest first, false = oldest first.
    function getRpIds(uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, string[] memory rpIds, uint256[] memory counts, uint256[] memory createdAts)
    {
        total = _rpIds.length;
        if (offset >= total) {
            return (total, new string[](0), new uint256[](0), new uint256[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        rpIds = new string[](count);
        counts = new uint256[](count);
        createdAts = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            string memory rp = _rpIds[idx];
            rpIds[i] = rp;
            counts[i] = _rpCredentials[rp].length;
            createdAts[i] = _rpCreatedAt[rp];
        }
    }

    /// @notice Paginated list of all keys under an rpId.
    /// @param rpId   The site domain.
    /// @param offset Number of items to skip.
    /// @param limit  Max items to return.
    /// @param desc   true = newest first, false = oldest first.
    function getKeysByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, PublicKeyRecord[] memory records)
    {
        string[] storage creds = _rpCredentials[rpId];
        total = creds.length;
        if (offset >= total) {
            return (total, new PublicKeyRecord[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        records = new PublicKeyRecord[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            bytes32 k = keccak256(abi.encode(rpId, creds[idx]));
            records[i] = _records[k];
        }
    }
}
