// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base64Url} from "./Base64Url.sol";

/// @title WebAuthnP256PublicKeyRegistry
/// @author Built by Vela Wallet (https://getvela.app)
/// @notice A neutral, permissionless, append-only registry of P-256 passkey
///         public keys. Anyone may store data about keys THEY HOLD; what the
///         keys are for — deriving a wallet, assembling an identity,
///         anything else — is entirely the storer's business, carried in the
///         unit's opaque `metadata`.
///
///         A registration UNIT is one GROUP KEY plus 1..7 member passkeys
///         sharing one rpId and one metadata payload, appended atomically
///         in ONE transaction. The group key is a client-held P-256 key
///         (typically generated per enrollment and discarded after); every
///         unit has exactly one, whether it carries one passkey or seven.
///         Each signer proves possession with a WebAuthn-formatted P-256
///         assertion over its storage-authorization challenge
///
///           keccak256(abi.encode(
///               block.chainid, address(registry), rpId,
///               signer.publicKey, binding))
///
///         verified on-chain via the EIP-7951 / RIP-7212 P256VERIFIER
///         precompile at 0x100 — where `binding` depends on the signer's
///         role:
///
///         - the GROUP KEY binds the unit's contentHash, covering the rpId,
///           the metadata, the group key itself and every member's
///           (publicKey, attestation). It vouches for the whole unit, so it
///           signs after the content is final — silently, since it is a
///           software key, never a ceremony;
///         - each MEMBER passkey binds memberBindingFor(groupPublicKey,
///           ownAttestation): it signs the moment it is created, knowing
///           only the group key and its own stored fields — independent of
///           every other member and of the metadata.
///
///         Together the signatures cover every byte: altering the metadata
///         or the member set invalidates the group signature; altering a
///         member's attestation invalidates that member; re-pairing a
///         member with a different group invalidates it; and reusing
///         proofs under the same group requires a fresh group signature
///         only the group key's holder can produce. Nothing is consumable
///         and nothing can be front-run: replaying a mined unit's public
///         proofs can only recreate the identical unit, which the
///         content-hash dedup rejects. Registration is idempotent, proofs
///         never need to be re-collected, and a mempool observer can do
///         nothing but pay the submitter's gas.
///
///         Nothing else is exclusive or interpreted:
///         - a passkey may appear in any number of units, and a group key
///           may index any number of units (readers get lists and filter by
///           their own schema);
///         - `metadata` (≤2048 bytes) is opaque: credential ids, display
///           names, wallet derivation preimages, group semantics — all
///           caller-defined;
///         - `attestation` per member (when present) is shape-checked: 20
///           versioned bytes of registration-time WebAuthn signals (AAGUID,
///           authData flags, attachment, transports); truthfulness is the
///           storer's claim;
///         - rpId is checked against every proof's authenticatorData
///           rpIdHash;
///         - identical unit content registers once, and the group key and
///           member keys within a unit are pairwise distinct: no
///           duplicates, and replay is inert by construction.
///
///         Readers locate data by public key: recover candidate keys from a
///         live assertion signature (one signature yields two; only a held
///         key can have entries, so at most one candidate's bucket is
///         non-empty), then read that bucket. Units are also indexed by
///         their group key (getUnitIdsByGroupKey). Entry and unit ids are
///         sequential and immutable — remember them for O(1) reads. A
///         unit's STABLE identity, computable offline before submission, is
///         its content hash (contentHashFor / getUnitIdByContentHash);
///         derive from that, never from the sequential unitId, which is
///         assigned only at mining time and can be shifted by concurrent
///         registrations.
///
///         Deployment requires a chain with the P256VERIFY precompile
///         (EIP-7951 / RIP-7212) at address 0x100.
contract WebAuthnP256PublicKeyRegistry {
    uint8 public constant VERSION = 8;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)
    /// Opaque caller-defined bytes; the registry never reads them.
    uint256 public constant MAX_METADATA_LENGTH = 2048;
    /// version(1) || AAGUID(16) || authData flags(1) || attachment(1) || transports(1)
    uint256 public constant ATTESTATION_LENGTH = 20;
    uint8 public constant ATTESTATION_VERSION = 1;
    /// Member passkeys per unit (the group key is on top of these).
    uint256 public constant MAX_MEMBERS = 7;

    /// EIP-7951 / RIP-7212 secp256r1 signature verification precompile.
    address public constant P256_VERIFIER = address(0x100);

    uint256 private constant _P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 private constant _P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    /// One registration unit: the shared payload of its member entries.
    struct Unit {
        string rpId;
        bytes metadata;
        bytes groupPublicKey;
        uint64 firstEntryId;
        uint32 memberCount;
        uint256 createdAt;
    }

    /// One stored entry: a member passkey within a unit.
    struct Entry {
        uint256 unitId;
        bytes publicKey;
        bytes attestation;
    }

    /// An entry joined with its unit, as returned by every read.
    struct EntryView {
        uint256 entryId;
        uint256 unitId;
        bytes publicKey;
        bytes attestation;
        string rpId;
        bytes metadata;
        bytes groupPublicKey;
        uint64 firstEntryId;
        uint32 memberCount;
        uint256 createdAt;
    }

    /// The WebAuthn-formatted possession proof: signature (r, s) by the
    /// signer's key over sha256(authenticatorData || sha256(clientDataJSON)),
    /// where clientDataJSON carries base64url(the signer's challenge) at
    /// challengeIndex and `"type":"webauthn.get"` at typeIndex. Non-WebAuthn
    /// P-256 holders — the group key included — synthesize the same shape.
    struct Proof {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeIndex;
        uint256 typeIndex;
        uint256 r;
        uint256 s;
    }

    /// One member passkey of a registration unit.
    struct Member {
        bytes publicKey;
        bytes attestation;
        Proof proof;
    }

    Unit[] private _units;
    Entry[] private _entries;

    // Indexes: entry ids per member key and per rpId; unit ids per group key.
    mapping(bytes32 => uint256[]) private _entriesByKey;
    mapping(string => uint256[]) private _entriesByRpId;
    mapping(bytes32 => uint256[]) private _unitsByGroupKey;

    /// Registered unit content, contentHash => unitId + 1 (0 = absent):
    /// identical unit content registers once, and the content hash doubles
    /// as the unit's stable, offline-computable identity.
    mapping(bytes32 => uint256) private _unitIdPlusOneByContent;

    // Enumeration support.
    string[] private _rpIds;
    mapping(string => uint256) private _rpCreatedAt;

    event UnitRegistered(
        uint256 indexed unitId,
        bytes32 indexed rpIdHash,
        bytes32 indexed groupKeyHash,
        uint256 firstEntryId,
        uint256 memberCount,
        bytes groupPublicKey
    );

    event EntryCreated(
        uint256 indexed entryId, bytes32 indexed keyHash, uint256 indexed unitId, bytes publicKey, bytes attestation
    );

    error EmptyRpId();
    error RpIdTooLong(uint256 length);
    error InvalidPublicKeyLength(uint256 length);
    error InvalidPublicKeyPrefix(bytes1 prefix);
    error InvalidPublicKeyCoordinate();
    error InvalidPublicKeyPoint();
    error MetadataTooLong(uint256 length);
    error InvalidAttestation(uint256 length);
    error InvalidMemberCount(uint256 count);
    error DuplicateMemberKey(uint256 index);
    error InvalidProof();
    error RpIdMismatch();
    error UnitAlreadyRegistered(bytes32 contentHash);
    error EntryNotFound(uint256 entryId);
    error UnitNotFound(uint256 unitId);

    // ── Validation ─────────────────────────────────────────────────────────

    function _validatePublicKey(bytes calldata publicKey) internal pure returns (uint256 x, uint256 y) {
        if (publicKey.length != UNCOMPRESSED_P256_KEY_LENGTH) {
            revert InvalidPublicKeyLength(publicKey.length);
        }
        if (publicKey[0] != 0x04) revert InvalidPublicKeyPrefix(publicKey[0]);

        x = uint256(bytes32(publicKey[1:33]));
        y = uint256(bytes32(publicKey[33:65]));

        if (x >= _P256_P || y >= _P256_P) revert InvalidPublicKeyCoordinate();

        uint256 lhs = mulmod(y, y, _P256_P);
        uint256 x2 = mulmod(x, x, _P256_P);
        uint256 x3 = mulmod(x2, x, _P256_P);
        uint256 rhs = addmod(addmod(x3, mulmod(_P256_P - 3, x, _P256_P), _P256_P), _P256_B, _P256_P);
        if (lhs != rhs) revert InvalidPublicKeyPoint();
    }

    function _validateRpId(string calldata rpId) internal pure {
        if (bytes(rpId).length == 0) revert EmptyRpId();
        if (bytes(rpId).length > MAX_RPID_LENGTH) {
            revert RpIdTooLong(bytes(rpId).length);
        }
    }

    /// @dev Opaque to the registry apart from its size cap.
    function _validateMetadata(bytes calldata metadata) internal pure {
        if (metadata.length > MAX_METADATA_LENGTH) {
            revert MetadataTooLong(metadata.length);
        }
    }

    /// @dev Empty (not recorded) or exactly 20 bytes starting with the
    ///      version byte. Content truthfulness is the storer's claim.
    function _validateAttestation(bytes calldata attestation) internal pure {
        if (attestation.length == 0) return;
        if (attestation.length != ATTESTATION_LENGTH || uint8(attestation[0]) != ATTESTATION_VERSION) {
            revert InvalidAttestation(attestation.length);
        }
    }

    // ── Possession proofs ──────────────────────────────────────────────────

    /// @notice The storage-authorization challenge one key signs: it binds
    ///         this chain, this registry, the rpId, the signer's own key
    ///         and a role-dependent `binding` — the unit's contentHash
    ///         (contentHashFor) for the group key, and
    ///         memberBindingFor(groupKey, ownAttestation) for member
    ///         passkeys, so members sign the moment their key exists.
    function challengeFor(string calldata rpId, bytes calldata publicKey, bytes32 binding)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), rpId, publicKey, binding));
    }

    /// @notice The binding a MEMBER passkey signs into its challenge: the
    ///         unit's group key plus the member's own attestation — both
    ///         known the moment the member's key is created, so no member
    ///         ever waits on another.
    function memberBindingFor(bytes calldata groupPublicKey, bytes calldata attestation)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(groupPublicKey, attestation));
    }

    /// @notice Whether identical unit content has already been registered.
    function isContentRegistered(bytes32 contentHash) external view returns (bool) {
        return _unitIdPlusOneByContent[contentHash] != 0;
    }

    /// @notice Resolve a unit by its stable identity, the content hash.
    function getUnitIdByContentHash(bytes32 contentHash) external view returns (bool exists, uint256 unitId) {
        uint256 idPlusOne = _unitIdPlusOneByContent[contentHash];
        if (idPlusOne == 0) return (false, 0);
        return (true, idPlusOne - 1);
    }

    /// @notice The content hash used for duplicate suppression — the unit's
    ///         stable identity, and what the group key signs.
    function contentHashFor(
        string calldata rpId,
        bytes calldata metadata,
        bytes calldata groupPublicKey,
        Member[] calldata members
    ) public pure returns (bytes32) {
        bytes32[] memory memberHashes = new bytes32[](members.length);
        for (uint256 i = 0; i < members.length; i++) {
            memberHashes[i] = keccak256(abi.encode(members[i].publicKey, members[i].attestation));
        }
        return keccak256(abi.encode(rpId, metadata, groupPublicKey, memberHashes));
    }

    function _checkSubstring(bytes memory data, uint256 offset, bytes memory expected) internal pure returns (bool) {
        if (offset + expected.length > data.length) return false;
        for (uint256 i = 0; i < expected.length; i++) {
            if (data[offset + i] != expected[i]) return false;
        }
        return true;
    }

    /// @dev Verifies one WebAuthn-shaped possession proof:
    ///      - authenticatorData is well-formed, its rpIdHash matches `rpId`,
    ///        and the UP (user present) flag is set;
    ///      - clientDataJSON carries `"type":"webauthn.get"` and
    ///        `"challenge":"<base64url(challenge)>"` at the given offsets;
    ///      - (r, s) verifies over sha256(authData || sha256(clientDataJSON))
    ///        under (x, y) via the P256VERIFY precompile.
    function _verifyProof(Proof calldata proof, bytes32 challenge, string calldata rpId, uint256 x, uint256 y)
        internal
        view
    {
        bytes memory authData = proof.authenticatorData;
        if (authData.length < 37) revert InvalidProof();
        if (bytes32(authData) != sha256(bytes(rpId))) revert RpIdMismatch();
        if (uint8(authData[32]) & 0x01 == 0) revert InvalidProof();

        bytes memory clientData = bytes(proof.clientDataJSON);
        if (!_checkSubstring(clientData, proof.typeIndex, bytes('"type":"webauthn.get"'))) {
            revert InvalidProof();
        }
        bytes memory expectedChallenge = bytes(string.concat('"challenge":"', Base64Url.encode32(challenge), '"'));
        if (!_checkSubstring(clientData, proof.challengeIndex, expectedChallenge)) {
            revert InvalidProof();
        }

        bytes32 digest = sha256(abi.encodePacked(authData, sha256(clientData)));
        (bool success, bytes memory output) = P256_VERIFIER.staticcall(abi.encode(digest, proof.r, proof.s, x, y));
        if (!success || output.length != 32 || bytes32(output) != bytes32(uint256(1))) {
            revert InvalidProof();
        }
    }

    // ── Write ──────────────────────────────────────────────────────────────

    /// @notice The one write entrypoint: append one unit — a group key plus
    ///         1..7 member passkeys — atomically. The group key authorizes
    ///         the whole unit (its assertion binds the contentHash); every
    ///         member authorizes the storage of its own key under this
    ///         group (binding the group key and its own attestation).
    ///         Identical content registers only once, making resubmission
    ///         idempotent.
    function register(
        string calldata rpId,
        bytes calldata metadata,
        bytes calldata groupPublicKey,
        Proof calldata groupProof,
        Member[] calldata members
    ) external {
        _validateRpId(rpId);
        _validateMetadata(metadata);
        if (members.length == 0 || members.length > MAX_MEMBERS) {
            revert InvalidMemberCount(members.length);
        }

        bytes32 contentHash = contentHashFor(rpId, metadata, groupPublicKey, members);
        if (_unitIdPlusOneByContent[contentHash] != 0) revert UnitAlreadyRegistered(contentHash);

        uint256 unitId = _units.length;
        _unitIdPlusOneByContent[contentHash] = unitId + 1;
        uint256 firstEntryId = _entries.length;
        _units.push(
            Unit({
                rpId: rpId,
                metadata: metadata,
                groupPublicKey: groupPublicKey,
                firstEntryId: uint64(firstEntryId),
                memberCount: uint32(members.length),
                createdAt: block.timestamp
            })
        );
        if (_entriesByRpId[rpId].length == 0) {
            _rpIds.push(rpId);
            _rpCreatedAt[rpId] = block.timestamp;
        }

        bytes32 groupKeyHash = keccak256(groupPublicKey);
        _unitsByGroupKey[groupKeyHash].push(unitId);
        _verifyGroup(rpId, groupPublicKey, groupProof, contentHash);

        // First pass: the group key and all member keys pairwise distinct.
        bytes32[] memory keyHashes = new bytes32[](members.length);
        for (uint256 i = 0; i < members.length; i++) {
            bytes32 keyHash = keccak256(members[i].publicKey);
            if (keyHash == groupKeyHash) revert DuplicateMemberKey(i);
            for (uint256 j = 0; j < i; j++) {
                if (keyHashes[j] == keyHash) revert DuplicateMemberKey(i);
            }
            keyHashes[i] = keyHash;
        }

        // Second pass: verify each member's group-scoped possession proof
        // and append the entry.
        for (uint256 i = 0; i < members.length; i++) {
            Member calldata member = members[i];
            (uint256 x, uint256 y) = _validatePublicKey(member.publicKey);
            _validateAttestation(member.attestation);
            bytes32 binding = memberBindingFor(groupPublicKey, member.attestation);
            _verifyProof(member.proof, challengeFor(rpId, member.publicKey, binding), rpId, x, y);

            uint256 entryId = _entries.length;
            _entries.push(Entry({unitId: unitId, publicKey: member.publicKey, attestation: member.attestation}));
            _entriesByKey[keyHashes[i]].push(entryId);
            _entriesByRpId[rpId].push(entryId);

            emit EntryCreated(entryId, keyHashes[i], unitId, member.publicKey, member.attestation);
        }

        emit UnitRegistered(unitId, keccak256(bytes(rpId)), groupKeyHash, firstEntryId, members.length, groupPublicKey);
    }

    /// @dev The group key's content-bound authorization for the whole unit.
    function _verifyGroup(
        string calldata rpId,
        bytes calldata groupPublicKey,
        Proof calldata groupProof,
        bytes32 contentHash
    ) internal view {
        (uint256 x, uint256 y) = _validatePublicKey(groupPublicKey);
        _verifyProof(groupProof, challengeFor(rpId, groupPublicKey, contentHash), rpId, x, y);
    }

    // ── Read ───────────────────────────────────────────────────────────────

    /// @notice Total number of units ever registered.
    function getTotalUnits() external view returns (uint256) {
        return _units.length;
    }

    /// @notice Total number of entries ever appended.
    function getTotalEntries() external view returns (uint256) {
        return _entries.length;
    }

    /// @notice One unit by its id.
    function getUnit(uint256 unitId) external view returns (Unit memory) {
        if (unitId >= _units.length) revert UnitNotFound(unitId);
        return _units[unitId];
    }

    /// @notice One entry (joined with its unit) by entry id. Ids are
    ///         sequential and never change: clients that remember their
    ///         entry ids read in O(1) forever.
    function getEntry(uint256 entryId) external view returns (EntryView memory) {
        if (entryId >= _entries.length) revert EntryNotFound(entryId);
        return _view(entryId);
    }

    /// @notice Whether a public key has any member entries. With possession
    ///         gating, at most one of a signature's recovered candidate
    ///         keys can.
    function hasEntries(bytes calldata publicKey) external view returns (bool) {
        return _entriesByKey[keccak256(publicKey)].length != 0;
    }

    /// @notice Number of member entries under a public key.
    function getTotalEntriesByKey(bytes calldata publicKey) external view returns (uint256) {
        return _entriesByKey[keccak256(publicKey)].length;
    }

    /// @notice Paginated member entries under a public key, in registration
    ///         order. Every one of them was written with that key's
    ///         signature.
    function getEntriesByKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, EntryView[] memory records)
    {
        return _page(_entriesByKey[keccak256(publicKey)], offset, limit, desc);
    }

    /// @notice Number of units under a group key.
    function getTotalUnitsByGroupKey(bytes calldata publicKey) external view returns (uint256) {
        return _unitsByGroupKey[keccak256(publicKey)].length;
    }

    /// @notice Paginated unit ids under a group key, in registration order.
    ///         Every listed unit carries that key's content-bound
    ///         signature; fetch bodies with getUnit.
    function getUnitIdsByGroupKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory unitIds)
    {
        uint256[] storage ids = _unitsByGroupKey[keccak256(publicKey)];
        total = ids.length;
        if (offset >= total) {
            return (total, new uint256[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        unitIds = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            unitIds[i] = ids[idx];
        }
    }

    /// @notice Number of member entries under an rpId.
    function getTotalEntriesByRpId(string calldata rpId) external view returns (uint256) {
        return _entriesByRpId[rpId].length;
    }

    /// @notice Paginated member entries under an rpId, in registration
    ///         order. Browse/stats convenience — synthetic (non-WebAuthn)
    ///         signers choose their own rpId, so treat aggregate views as
    ///         cosmetic.
    function getEntriesByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, EntryView[] memory records)
    {
        return _page(_entriesByRpId[rpId], offset, limit, desc);
    }

    /// @notice Total number of distinct rpIds.
    function getTotalRpIds() external view returns (uint256) {
        return _rpIds.length;
    }

    /// @notice Paginated list of all rpIds with entry counts and first-use times.
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
            counts[i] = _entriesByRpId[rp].length;
            createdAts[i] = _rpCreatedAt[rp];
        }
    }

    function _view(uint256 entryId) internal view returns (EntryView memory) {
        Entry storage entry = _entries[entryId];
        Unit storage unit = _units[entry.unitId];
        return EntryView({
            entryId: entryId,
            unitId: entry.unitId,
            publicKey: entry.publicKey,
            attestation: entry.attestation,
            rpId: unit.rpId,
            metadata: unit.metadata,
            groupPublicKey: unit.groupPublicKey,
            firstEntryId: unit.firstEntryId,
            memberCount: unit.memberCount,
            createdAt: unit.createdAt
        });
    }

    function _page(uint256[] storage ids, uint256 offset, uint256 limit, bool desc)
        internal
        view
        returns (uint256 total, EntryView[] memory records)
    {
        total = ids.length;
        if (offset >= total) {
            return (total, new EntryView[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        records = new EntryView[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            records[i] = _view(ids[idx]);
        }
    }
}
