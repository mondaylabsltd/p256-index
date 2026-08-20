// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {WebAuthnP256PublicKeyIndex} from "./WebAuthnP256PublicKeyIndex.sol";

/// @title WebAuthnP256PublicKeyIndexV3
/// @author Built by Vela Wallet (https://getvela.app)
/// @notice Stores WebAuthn P256 passkey public keys on-chain.
///         Single source of truth for all chains. Records are append-only.
///         (rpId, credentialId) is globally unique — first come, first served.
///         V3: a walletRef may be shared by multiple credentials (multi-passkey
///         wallets), so wallets and credentials are counted separately.
///         V2 records stay readable: getRecord / getRecordByWalletRef / hasRecord
///         fall through to the V2 index when V3 has no match, and createRecord
///         keeps both keyspaces disjoint so a V2 record can never be shadowed.
///         On chains where V2 is not deployed the fallback short-circuits.
contract WebAuthnP256PublicKeyIndexV3 {
    uint8 public constant VERSION = 3;

    /// @notice The V2 index read through by the fallback paths. Same address on every chain.
    address public constant V2_ADDRESS = 0xdd93420BD49baaBdFF4A363DdD300622Ae87E9c3;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant MAX_CREDENTIAL_ID_LENGTH = 1024;
    uint256 public constant MAX_NAME_LENGTH = 256;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)
    // Metadata is the wallet's derivation preimage, raw-packed:
    // METADATA_PREFIX || pk1 || .. || pkN  (32 + 65*N bytes).
    // 1397 = 32 + 65*21: a wallet is derived from at most 21 passkeys.
    uint256 public constant MAX_METADATA_LENGTH = 1397;
    uint256 public constant MAX_METADATA_KEYS = 21;
    bytes32 public constant METADATA_PREFIX = "VelaWalletV1"; // right-padded to 32 bytes
    // Domain separator for createWallet commitments, so the two commitment
    // formulas can never collide.
    bytes32 public constant WALLET_COMMIT_TAG = "V3.createWallet";
    uint256 public constant REVEAL_DELAY = 1;

    uint256 private constant _P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 private constant _P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;
    uint256 private constant _METADATA_PREFIX_LENGTH = 32;

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

    struct CreateParams {
        string rpId;
        string credentialId;
        bytes32 walletRef;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
    }

    /// One member of a multi-key wallet: its credential and key, in derivation order.
    struct WalletMember {
        string credentialId;
        bytes publicKey;
        string name;
    }

    mapping(bytes32 => PublicKeyRecord) private _records;
    mapping(bytes32 => uint256) private _commitBlockPlusOne;

    // Enumeration support
    uint256 private _totalCredentials;
    string[] private _rpIds;
    mapping(string => uint256) private _rpCreatedAt;
    mapping(string => string[]) private _rpCredentials;
    bytes32[] private _walletRefs;
    mapping(bytes32 => uint256) private _walletCreatedAt;
    // The wallet's member records, written exactly once: by createRecord for a
    // single-key wallet or atomically by createWallet for a multi-key wallet.
    // A non-empty array means the walletRef is permanently claimed.
    mapping(bytes32 => bytes32[]) private _recordKeysByWalletRef;

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

    event WalletCreated(bytes32 indexed walletRef, string rpId, uint256 memberCount);

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
    error InvalidMetadataFormat();
    error MetadataNotOwnSingleKey();
    error InvalidMemberCount(uint256 count);
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

    /// @dev Consume a commit-reveal commitment: exactly one reveal per commit.
    function _consumeCommit(bytes32 commitment) internal {
        uint256 commitBlockPlusOne = _commitBlockPlusOne[commitment];
        if (commitBlockPlusOne == 0) revert NotCommitted();
        if (block.number < (commitBlockPlusOne - 1) + REVEAL_DELAY) {
            revert RevealTooEarly();
        }
        delete _commitBlockPlusOne[commitment];
    }

    // ── V2 fallback ──

    function _v2() internal pure returns (WebAuthnP256PublicKeyIndex) {
        return WebAuthnP256PublicKeyIndex(V2_ADDRESS);
    }

    /// @dev False on chains where the V2 index was never deployed — every fallback short-circuits.
    function _v2Live() internal view returns (bool) {
        return V2_ADDRESS.code.length != 0;
    }

    /// @dev True iff the raw revert data is exactly V2's WalletRefNotFound(bytes32).
    function _isWalletRefNotFound(bytes memory reason) private pure returns (bool) {
        if (reason.length != 36) return false;
        bytes4 sel;
        assembly ("memory-safe") {
            sel := mload(add(reason, 32))
        }
        return sel == WalletRefNotFound.selector;
    }

    function _revertWith(bytes memory reason) private pure {
        assembly ("memory-safe") {
            revert(add(reason, 32), mload(reason))
        }
    }

    function _v2HasWalletRef(bytes32 walletRef) internal view returns (bool) {
        if (!_v2Live()) return false;
        try _v2().getRecordByWalletRef(walletRef) returns (WebAuthnP256PublicKeyIndex.PublicKeyRecord memory) {
            return true;
        } catch (bytes memory reason) {
            // Only a genuine WalletRefNotFound means "absent". Anything else
            // (out-of-gas, unexpected revert) must fail closed, not report absence.
            if (!_isWalletRefNotFound(reason)) _revertWith(reason);
            return false;
        }
    }

    function _fromV2(WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r)
        internal
        pure
        returns (PublicKeyRecord memory)
    {
        return PublicKeyRecord({
            rpId: r.rpId,
            credentialId: r.credentialId,
            walletRef: r.walletRef,
            publicKey: r.publicKey,
            name: r.name,
            initialCredentialId: r.initialCredentialId,
            // V2 stored metadata in an older encoding; normalize to the packed
            // convention so every record read through V3 has the same format.
            metadata: abi.encodePacked(METADATA_PREFIX, r.publicKey),
            createdAt: r.createdAt
        });
    }

    // ── Write ──

    /// @notice Commit a future record registration. Must be called before createRecord.
    /// @param commitment keccak256(abi.encode(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata, credentialsRoot))
    function commit(bytes32 commitment) external {
        if (_commitBlockPlusOne[commitment] == 0) {
            _commitBlockPlusOne[commitment] = block.number + 1;
        }
    }

    /// @notice Batch commit in one transaction (folded in from the V2-era helper).
    function batchCommit(bytes32[] calldata commitments) external {
        for (uint256 i = 0; i < commitments.length; i++) {
            if (_commitBlockPlusOne[commitments[i]] == 0) {
                _commitBlockPlusOne[commitments[i]] = block.number + 1;
            }
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
    ///                  Multiple credentials may share one walletRef (a wallet derived from several passkeys).
    /// @param metadata The wallet's derivation preimage, raw-packed and mandatory:
    ///                 METADATA_PREFIX || pk1 || .. || pkN — the ordered pubkey set the
    ///                 wallet address is derived from. Structure is enforced on-chain,
    ///                 it must contain this record's own publicKey, and all members of
    ///                 one wallet must carry byte-identical metadata (pinned on first write).
    function createRecord(
        string calldata rpId,
        string calldata credentialId,
        bytes32 walletRef,
        bytes calldata publicKey,
        string calldata name,
        string calldata initialCredentialId,
        bytes calldata metadata
    ) external {
        _create(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata);
    }

    /// @notice Batch create in one transaction (folded in from the V2-era helper).
    function batchCreateRecord(CreateParams[] calldata params) external {
        for (uint256 i = 0; i < params.length; i++) {
            CreateParams calldata p = params[i];
            _create(p.rpId, p.credentialId, p.walletRef, p.publicKey, p.name, p.initialCredentialId, p.metadata);
        }
    }

    function _create(
        string calldata rpId,
        string calldata credentialId,
        bytes32 walletRef,
        bytes calldata publicKey,
        string calldata name,
        string calldata initialCredentialId,
        bytes calldata metadata
    ) internal {
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
        // createRecord registers SINGLE-key wallets only: metadata must be
        // exactly the prefix word plus this record's own key. Multi-key
        // wallets go through createWallet (one commit, one atomic reveal).
        if (keccak256(metadata) != keccak256(abi.encodePacked(METADATA_PREFIX, publicKey))) {
            revert MetadataNotOwnSingleKey();
        }
        if (walletRef == bytes32(0)) revert EmptyWalletRef();

        // Verify commit-reveal
        _consumeCommit(
            keccak256(abi.encode(rpId, credentialId, walletRef, publicKey, name, initialCredentialId, metadata))
        );

        bytes32 k = _recordKey(rpId, credentialId);
        if (_recordExists(k)) {
            revert RecordAlreadyExists(rpId, credentialId);
        }

        // walletRef is one-to-one on this path: any existing V3 wallet —
        // single- or multi-key — has already claimed it permanently.
        if (_recordKeysByWalletRef[walletRef].length != 0) {
            revert WalletRefAlreadyExists(walletRef);
        }

        // The V2 and V3 keyspaces stay disjoint: reads prefer V3, so a credential
        // or wallet living in V2 must never be shadowable by a V3 registration.
        if (_v2Live()) {
            if (_v2().hasRecord(rpId, credentialId)) {
                revert RecordAlreadyExists(rpId, credentialId);
            }
            if (_v2HasWalletRef(walletRef)) {
                revert WalletRefAlreadyExists(walletRef);
            }
        }

        // initialCredentialId must equal credentialId (initial key) or reference an
        // existing root record — in V3 first, else in the V2 shard.
        if (keccak256(bytes(initialCredentialId)) != keccak256(bytes(credentialId))) {
            bytes32 initKey = _recordKey(rpId, initialCredentialId);
            if (_recordExists(initKey)) {
                if (keccak256(bytes(_records[initKey].initialCredentialId)) != keccak256(bytes(initialCredentialId))) {
                    revert InitialRecordNotRoot(rpId, initialCredentialId);
                }
            } else if (_v2Live() && _v2().hasRecord(rpId, initialCredentialId)) {
                WebAuthnP256PublicKeyIndex.PublicKeyRecord memory v2Init = _v2().getRecord(rpId, initialCredentialId);
                if (keccak256(bytes(v2Init.initialCredentialId)) != keccak256(bytes(initialCredentialId))) {
                    revert InitialRecordNotRoot(rpId, initialCredentialId);
                }
            } else {
                revert InitialRecordNotFound(rpId, initialCredentialId);
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
        _recordKeysByWalletRef[walletRef].push(k);
        _walletRefs.push(walletRef);
        _walletCreatedAt[walletRef] = block.timestamp;
        _totalCredentials++;

        emit RecordCreated(
            k, keccak256(bytes(rpId)), walletRef, rpId, credentialId, publicKey, name, initialCredentialId, metadata
        );
    }

    /// @notice Register a multi-key wallet atomically: all member credentials,
    ///         one walletRef, ONE commitment, one reveal. The derivation
    ///         preimage (metadata) is constructed on-chain from the ordered
    ///         member keys, so every member record carries the identical set
    ///         by construction. Commitment:
    ///         keccak256(abi.encode(WALLET_COMMIT_TAG, rpId, walletRef, members)).
    function createWallet(string calldata rpId, bytes32 walletRef, WalletMember[] calldata members) external {
        if (bytes(rpId).length == 0) revert EmptyRpId();
        if (bytes(rpId).length > MAX_RPID_LENGTH) {
            revert RpIdTooLong(bytes(rpId).length);
        }
        if (members.length == 0 || members.length > MAX_METADATA_KEYS) {
            revert InvalidMemberCount(members.length);
        }
        if (walletRef == bytes32(0)) revert EmptyWalletRef();

        // Verify commit-reveal: the whole bundle is protected as one unit.
        _consumeCommit(keccak256(abi.encode(WALLET_COMMIT_TAG, rpId, walletRef, members)));

        if (_recordKeysByWalletRef[walletRef].length != 0) {
            revert WalletRefAlreadyExists(walletRef);
        }
        if (_v2HasWalletRef(walletRef)) {
            revert WalletRefAlreadyExists(walletRef);
        }

        // Build the derivation preimage from the ordered member keys.
        bytes memory metadata = abi.encodePacked(METADATA_PREFIX);
        for (uint256 i = 0; i < members.length; i++) {
            _validatePublicKey(members[i].publicKey);
            metadata = bytes.concat(metadata, members[i].publicKey);
        }

        for (uint256 i = 0; i < members.length; i++) {
            WalletMember calldata member = members[i];
            if (bytes(member.credentialId).length == 0) revert EmptyCredentialId();
            if (bytes(member.credentialId).length > MAX_CREDENTIAL_ID_LENGTH) {
                revert CredentialIdTooLong(bytes(member.credentialId).length);
            }
            if (bytes(member.name).length > MAX_NAME_LENGTH) {
                revert NameTooLong(bytes(member.name).length);
            }
            bytes32 k = _recordKey(rpId, member.credentialId);
            if (_recordExists(k)) {
                revert RecordAlreadyExists(rpId, member.credentialId);
            }
            if (_v2Live() && _v2().hasRecord(rpId, member.credentialId)) {
                revert RecordAlreadyExists(rpId, member.credentialId);
            }
            _records[k] = PublicKeyRecord({
                rpId: rpId,
                credentialId: member.credentialId,
                walletRef: walletRef,
                publicKey: member.publicKey,
                name: member.name,
                initialCredentialId: member.credentialId,
                metadata: metadata,
                createdAt: block.timestamp
            });
            if (_rpCredentials[rpId].length == 0) {
                _rpIds.push(rpId);
                _rpCreatedAt[rpId] = block.timestamp;
            }
            _rpCredentials[rpId].push(member.credentialId);
            _recordKeysByWalletRef[walletRef].push(k);
            _totalCredentials++;

            emit RecordCreated(
                k,
                keccak256(bytes(rpId)),
                walletRef,
                rpId,
                member.credentialId,
                member.publicKey,
                member.name,
                member.credentialId,
                metadata
            );
        }

        _walletRefs.push(walletRef);
        _walletCreatedAt[walletRef] = block.timestamp;
        emit WalletCreated(walletRef, rpId, members.length);
    }

    // ── Read ──

    /// @notice Query a record by rpId and credentialId. Falls through to the V2 index on a V3 miss.
    function getRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (PublicKeyRecord memory)
    {
        bytes32 k = _recordKey(rpId, credentialId);
        if (_recordExists(k)) {
            return _records[k];
        }
        if (_v2Live()) {
            // Bubbles V2's RecordNotFound (identical selector) when absent there too.
            return _fromV2(_v2().getRecord(rpId, credentialId));
        }
        revert RecordNotFound(rpId, credentialId);
    }

    /// @notice Query the wallet's first record. Falls through to the V2 index on
    ///         a V3 miss. The record's metadata carries the wallet's full ordered
    ///         pubkey set, so one read resolves the whole member set.
    /// @dev    Registration is permissionless, so the wallet slot is not authenticated:
    ///         consumers MUST verify that the wallet address derived from the record's
    ///         metadata pubkey set equals walletRef before trusting the key material.
    function getRecordByWalletRef(bytes32 walletRef) external view returns (PublicKeyRecord memory) {
        bytes32[] storage keys = _recordKeysByWalletRef[walletRef];
        if (keys.length != 0) {
            return _records[keys[0]];
        }
        if (_v2Live()) {
            // Bubbles V2's WalletRefNotFound (identical selector) when absent there too.
            return _fromV2(_v2().getRecordByWalletRef(walletRef));
        }
        revert WalletRefNotFound(walletRef);
    }

    /// @notice Paginated list of a wallet's member records (its credentialIds and
    ///         keys, in registration order). A walletRef with no V3 records but a
    ///         V2 record reports that single V2 record.
    /// @param walletRef The wallet identifier.
    /// @param offset    Number of items to skip.
    /// @param limit     Max items to return.
    /// @param desc      true = newest first, false = oldest first.
    function getRecordsByWalletRef(bytes32 walletRef, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, PublicKeyRecord[] memory records)
    {
        bytes32[] storage keys = _recordKeysByWalletRef[walletRef];
        total = keys.length;
        if (total == 0 && _v2Live()) {
            try _v2().getRecordByWalletRef(walletRef) returns (WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r) {
                if (offset == 0 && limit > 0) {
                    records = new PublicKeyRecord[](1);
                    records[0] = _fromV2(r);
                    return (1, records);
                }
                return (1, new PublicKeyRecord[](0));
            } catch (bytes memory reason) {
                if (!_isWalletRefNotFound(reason)) _revertWith(reason);
                return (0, new PublicKeyRecord[](0));
            }
        }
        if (offset >= total) {
            return (total, new PublicKeyRecord[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        records = new PublicKeyRecord[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            records[i] = _records[keys[idx]];
        }
    }

    /// @notice Number of member records under a walletRef (1 for a V2-era wallet).
    function getTotalCredentialsByWalletRef(bytes32 walletRef) external view returns (uint256) {
        uint256 n = _recordKeysByWalletRef[walletRef].length;
        if (n == 0 && _v2HasWalletRef(walletRef)) {
            return 1;
        }
        return n;
    }

    /// @notice Check if a record exists in V3 or in the V2 index.
    function hasRecord(string calldata rpId, string calldata credentialId) external view returns (bool) {
        if (_recordExists(_recordKey(rpId, credentialId))) {
            return true;
        }
        return _v2Live() && _v2().hasRecord(rpId, credentialId);
    }

    /// @notice Get the number of credentials registered under an rpId.
    function getTotalCredentialsByRpId(string calldata rpId) external view returns (uint256) {
        return _rpCredentials[rpId].length;
    }

    /// @notice Total number of credentials registered in V3. V2 history is excluded
    ///         by design — query the V2 index directly and add off-chain if needed.
    function getTotalCredentials() external view returns (uint256) {
        return _totalCredentials;
    }

    /// @notice Total number of distinct wallets (walletRefs) registered in V3.
    ///         A wallet with N passkeys counts once. V2 history is excluded by design.
    function getTotalWallets() external view returns (uint256) {
        return _walletRefs.length;
    }

    /// @notice Paginated list of all V3-native wallets with key counts and creation times.
    ///         V2-era wallets are neither enumerated nor counted here (each V2 credential is
    ///         its own one-key wallet; browse those via the V2 index).
    /// @param offset Number of items to skip.
    /// @param limit  Max items to return.
    /// @param desc   true = newest first, false = oldest first.
    /// @return total V3-native wallet count (the range offset/limit paginates over).
    /// @return walletRefs The page of wallet identifiers.
    /// @return counts Each wallet's member-record count.
    /// @return createdAts Each wallet's creation timestamp.
    function getWalletRefs(uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, bytes32[] memory walletRefs, uint256[] memory counts, uint256[] memory createdAts)
    {
        total = _walletRefs.length;
        if (offset >= total) {
            return (total, new bytes32[](0), new uint256[](0), new uint256[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        walletRefs = new bytes32[](count);
        counts = new uint256[](count);
        createdAts = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            bytes32 w = _walletRefs[idx];
            walletRefs[i] = w;
            counts[i] = _recordKeysByWalletRef[w].length;
            createdAts[i] = _walletCreatedAt[w];
        }
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
