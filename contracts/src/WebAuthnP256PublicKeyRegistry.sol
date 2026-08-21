// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Base64Url} from "./Base64Url.sol";

/// @title WebAuthnP256PublicKeyRegistry
/// @author Built by Vela Wallet (https://getvela.app)
/// @notice A neutral, permissionless, append-only registry of P-256 passkey
///         public keys, organised as three plain tables and TWO write
///         operations:
///
///         - ENTRY — the global file of one passkey: exactly one row per
///           public key, ever. Created the first time the key appears; its
///           attestation is fixed there, signed by the key itself,
///           immutable after.
///         - UNIT (group), written by `register` — one row per group key,
///           ever. Its whole content (rpId, opaque metadata, the group key
///           and the member set, digested as contentHash) is FROZEN at
///           creation: a group's members can never change. What a group
///           means — a wallet, an identity, anything — is entirely the
///           storer's business, carried in the opaque `metadata`.
///         - REFERENCE, written by `refer` — one passkey pointing at one
///           existing group, in its own table with its own counters,
///           never mixed with groups. A reference is DISCOVERY data, not
///           authority: it lets a later-added device find its group, and
///           it never touches the group's frozen record or indexes.
///           Whether a referenced key means anything is the reader's
///           schema's decision (e.g. against the wallet layer's own owner
///           set).
///
///         Every signature is a WebAuthn-formatted P-256 assertion over a
///         storage-authorization challenge
///
///           keccak256(abi.encode(
///               block.chainid, address(registry), rpId,
///               signer.publicKey, binding))
///
///         verified on-chain via the EIP-7951 / RIP-7212 P256VERIFIER
///         precompile at 0x100, where `binding` depends on the signer's
///         role:
///
///         - the GROUP KEY (a client-held software key, generated for the
///           one register call and discarded after — group keys are
///           single-use) binds the group's contentHash, vouching for the
///           whole frozen record, silently, never a ceremony;
///         - a MEMBER passkey binds memberBindingFor(groupPublicKey,
///           ownAttestation) — signable the moment the key is created,
///           independent of the metadata and of every other member;
///         - a REFERRING passkey binds referenceBindingFor(groupPublicKey,
///           ownAttestation, referenceMetadata) — also signable the moment
///           the key is created.
///
///         Every byte is signature-covered, so nothing is consumable and
///         nothing can be front-run: altering any field invalidates its
///         signature, and replaying a mined call can only recreate state
///         that already exists (group keys are single-use, memberships and
///         references are unique per pair). Nobody can create an entry, a
///         membership or a reference for a key they do not hold.
///
///         Nothing else is exclusive or interpreted:
///         - a passkey ENTRY is global and reusable: the same key may be a
///           member of any number of groups and hold any number of
///           references, yet is always one row — getTotalEntries() IS the
///           passkey count, getTotalUnits() IS the group count,
///           getTotalReferences() IS the reference count, three
///           independent tables;
///         - `metadata` (≤2048 bytes, on groups and on references) is
///           opaque; `attestation` (empty or 20 versioned bytes of
///           registration-time WebAuthn signals) is shape-checked, its
///           truthfulness the storer's claim;
///         - rpId is checked against every proof's authenticatorData
///           rpIdHash, but synthetic (non-WebAuthn) signers choose their
///           own rpId — treat rpId aggregates as cosmetic. Likewise,
///           anyone holding any key can refer it to any group, so a
///           group's incoming-reference list is cosmetic too; the
///           authenticated directions are per-key;
///         - key ROLES are separate namespaces, distinct only within one
///           call: a used group key may later hold an entry (by joining
///           another group as a member, or referring), and an
///           entry-holding key may open a group as its group key. The
///           structural counters are unaffected — entries stay unique per
///           key, groups unique per group key.
///
///         Readers locate data by public key: recover candidate keys from
///         a live assertion signature (one signature yields two; only a
///         held key can have an entry, so at most one candidate resolves),
///         then getEntryByKey → getGroupsOfKey / getReferencesOfKey →
///         getUnit. Entry, unit and reference ids are sequential and
///         immutable; a group's stable identity is its group public key
///         (equivalently its contentHash), never the sequential unitId.
///
///         Deployment requires a chain with the P256VERIFY precompile
///         (EIP-7951 / RIP-7212) at address 0x100.
contract WebAuthnP256PublicKeyRegistry {
    uint8 public constant VERSION = 11;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)
    /// Opaque caller-defined bytes; the registry never reads them.
    uint256 public constant MAX_METADATA_LENGTH = 2048;
    /// The 20-byte versioned attestation, layout:
    ///   version(1) || AAGUID(16) || authenticatorData flags(1) || reserved(2)
    /// All of it is derived from the WebAuthn attestation object's authData
    /// and interpretable by the standard: the AAGUID identifies the
    /// authenticator model (FIDO Metadata Service), the flags byte carries the
    /// UP/UV/BE/BS/AT/ED bits. The two reserved bytes are 0x0000. Note that
    /// authenticatorAttachment and transports are NOT authData fields (they
    /// come from the PublicKeyCredential response), so they are deliberately
    /// not packed here — a lossy single-byte encoding of them would be
    /// Vela-specific and not standard-interpretable.
    uint256 public constant ATTESTATION_LENGTH = 20;
    uint8 public constant ATTESTATION_VERSION = 1;
    /// Upper bound on the stored WebAuthn credential id (spec max is 1023).
    uint256 public constant MAX_CREDENTIAL_ID_LENGTH = 1023;
    /// Upper bounds on the stored PublicKeyCredential response hints. These
    /// come from the browser (authenticatorAttachment string, transports
    /// array), not from authData, so they are store-only display metadata —
    /// captured at first sight and never contested. Attachment holds a short
    /// token ("platform" / "cross-platform"); transports holds the transport
    /// tokens joined however the writer chooses (e.g. "hybrid,internal").
    uint256 public constant MAX_AUTHENTICATOR_ATTACHMENT_LENGTH = 32;
    uint256 public constant MAX_TRANSPORTS_LENGTH = 255;
    /// Member passkeys per group (the group key is on top of these).
    uint256 public constant MAX_MEMBERS = 7;

    /// EIP-7951 / RIP-7212 secp256r1 signature verification precompile.
    address public constant P256_VERIFIER = address(0x100);

    uint256 private constant _P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    uint256 private constant _P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b;

    /// The global file of one passkey: one row per public key, ever.
    struct Entry {
        bytes publicKey;
        bytes attestation;
        /// The WebAuthn credential id, as supplied by the possession-proving
        /// writer at first sight. Stored for local lookup and display; it is
        /// NOT part of the signed content (a local handle, not authority).
        bytes credentialId;
        /// PublicKeyCredential response hints (browser-reported, not authData,
        /// not signed): the authenticatorAttachment token and the transports
        /// list. Captured at first sight for display; first write wins.
        bytes authenticatorAttachment;
        bytes transports;
        uint256 createdAt;
    }

    /// One group: frozen at creation, never modified.
    struct Unit {
        string rpId;
        bytes metadata;
        bytes groupPublicKey;
        /// keccak over (rpId, metadata, groupPublicKey, member hashes) —
        /// the group's stable, offline-computable identity.
        bytes32 contentHash;
        uint32 memberCount;
        uint256 createdAt;
    }

    /// One passkey pointing at one group: discovery data in its own table.
    struct Reference {
        uint256 entryId;
        uint256 unitId;
        bytes metadata;
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

    /// One member passkey of a group.
    struct Member {
        bytes publicKey;
        bytes attestation;
        /// The WebAuthn credential id (stored on the entry, not signed).
        bytes credentialId;
        /// PublicKeyCredential response hints (stored on the entry, not
        /// signed): authenticatorAttachment token and transports list.
        bytes authenticatorAttachment;
        bytes transports;
        Proof proof;
    }

    Entry[] private _entries;
    Unit[] private _units;
    Reference[] private _references;

    // Single-valued identity indexes (value = id + 1; 0 = absent).
    mapping(bytes32 => uint256) private _entryIdPlusOneByKey;
    mapping(bytes32 => uint256) private _unitIdPlusOneByGroupKey;
    mapping(bytes32 => uint256) private _unitIdPlusOneByContent;

    // The membership relation, written once per group at register time,
    // indexed both ways, plus an O(1) existence check.
    mapping(uint256 => uint256[]) private _groupEntryIds;
    mapping(uint256 => uint256[]) private _entryUnitIds;
    mapping(uint256 => mapping(uint256 => bool)) private _isMemberLink;

    // The reference relation: its own table and indexes, never mixed with
    // groups or memberships. One reference per (group, key) pair; the link
    // mapping stores referenceId + 1 (0 = absent).
    mapping(uint256 => uint256[]) private _referenceIdsByEntry;
    mapping(uint256 => uint256[]) private _referenceIdsByUnit;
    mapping(uint256 => mapping(uint256 => uint256)) private _referenceIdPlusOneByLink;

    // rpId enumeration (cosmetic browse/stats: groups per rpId).
    string[] private _rpIds;
    mapping(string => uint256) private _rpCreatedAt;
    mapping(string => uint256[]) private _unitIdsByRpId;

    event EntryCreated(
        uint256 indexed entryId, bytes32 indexed keyHash, bytes publicKey, bytes attestation, bytes credentialId
    );

    event GroupCreated(
        uint256 indexed unitId,
        bytes32 indexed rpIdHash,
        bytes32 indexed groupKeyHash,
        bytes groupPublicKey,
        uint256 memberCount
    );

    event MemberJoined(uint256 indexed unitId, uint256 indexed entryId, bytes32 indexed keyHash);

    event ReferenceCreated(
        uint256 indexed referenceId,
        uint256 indexed entryId,
        uint256 indexed unitId,
        bytes32 keyHash,
        bytes32 groupKeyHash
    );

    error EmptyRpId();
    error RpIdTooLong(uint256 length);
    error InvalidPublicKeyLength(uint256 length);
    error InvalidPublicKeyPrefix(bytes1 prefix);
    error InvalidPublicKeyCoordinate();
    error InvalidPublicKeyPoint();
    error MetadataTooLong(uint256 length);
    error InvalidAttestation(uint256 length);
    error CredentialIdTooLong(uint256 length);
    error CredentialIdMismatch(uint256 entryId);
    error AuthenticatorAttachmentTooLong(uint256 length);
    error TransportsTooLong(uint256 length);
    error AttestationMismatch(uint256 entryId);
    error InvalidMemberCount(uint256 count);
    error DuplicateMemberKey(uint256 index);
    error GroupKeyAlreadyUsed(bytes32 groupKeyHash);
    error GroupNotFound(bytes32 groupKeyHash);
    error AlreadyReferenced(uint256 referenceId);
    error InvalidProof();
    error RpIdMismatch();
    error EntryNotFound(uint256 entryId);
    error UnitNotFound(uint256 unitId);
    error ReferenceNotFound(uint256 referenceId);

    // ── Validation ─────────────────────────────────────────────────────────

    function _validatePublicKey(bytes memory publicKey) internal pure returns (uint256 x, uint256 y) {
        if (publicKey.length != UNCOMPRESSED_P256_KEY_LENGTH) {
            revert InvalidPublicKeyLength(publicKey.length);
        }
        if (publicKey[0] != 0x04) revert InvalidPublicKeyPrefix(publicKey[0]);

        assembly ("memory-safe") {
            x := mload(add(publicKey, 33))
            y := mload(add(publicKey, 65))
        }

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
    function _validateAttestation(bytes memory attestation) internal pure {
        if (attestation.length == 0) return;
        if (attestation.length != ATTESTATION_LENGTH || uint8(attestation[0]) != ATTESTATION_VERSION) {
            revert InvalidAttestation(attestation.length);
        }
    }

    // ── Challenges and digests ─────────────────────────────────────────────

    /// @notice The storage-authorization challenge one key signs: it binds
    ///         this chain, this registry, the rpId, the signer's own key
    ///         and a role-dependent `binding` — the group's contentHash for
    ///         the group key, memberBindingFor for a member passkey,
    ///         referenceBindingFor for a referring passkey.
    function challengeFor(string memory rpId, bytes memory publicKey, bytes32 binding)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), rpId, publicKey, binding));
    }

    /// @notice The binding a MEMBER passkey signs into its challenge: the
    ///         group key plus the member's own attestation — both known the
    ///         moment the member's key is created, so no member ever waits
    ///         on another.
    function memberBindingFor(bytes memory groupPublicKey, bytes memory attestation)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(groupPublicKey, attestation));
    }

    /// @notice The binding a REFERRING passkey signs: the target group key
    ///         plus the passkey's own attestation and the reference's
    ///         opaque metadata — all known the moment the key is created.
    function referenceBindingFor(bytes memory groupPublicKey, bytes memory attestation, bytes memory metadata)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(groupPublicKey, attestation, metadata));
    }

    /// @notice The group's frozen founding digest — its stable, offline-
    ///         computable identity, and what the group key signs.
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
    function _verifyProof(Proof calldata proof, bytes32 challenge, string memory rpId, uint256 x, uint256 y)
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

    // ── Write 1: register a group ──────────────────────────────────────────

    /// @notice Create one group: its frozen record (rpId, metadata, group
    ///         key, member set) plus one membership row per member. The
    ///         group key must never have been used; brand-new passkeys get
    ///         their global entry created on the way. Immutable after —
    ///         there is deliberately no way to change a group's members.
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

        bytes32 groupKeyHash = keccak256(groupPublicKey);
        if (_unitIdPlusOneByGroupKey[groupKeyHash] != 0) revert GroupKeyAlreadyUsed(groupKeyHash);

        bytes32 contentHash = contentHashFor(rpId, metadata, groupPublicKey, members);
        uint256 unitId = _units.length;
        _units.push(
            Unit({
                rpId: rpId,
                metadata: metadata,
                groupPublicKey: groupPublicKey,
                contentHash: contentHash,
                memberCount: uint32(members.length),
                createdAt: block.timestamp
            })
        );
        _unitIdPlusOneByGroupKey[groupKeyHash] = unitId + 1;
        _unitIdPlusOneByContent[contentHash] = unitId + 1;
        if (_unitIdsByRpId[rpId].length == 0) {
            _rpIds.push(rpId);
            _rpCreatedAt[rpId] = block.timestamp;
        }
        _unitIdsByRpId[rpId].push(unitId);

        _verifyGroup(rpId, groupPublicKey, groupProof, contentHash);

        // Pairwise-distinct member keys, none equal to the group key.
        bytes32[] memory keyHashes = new bytes32[](members.length);
        for (uint256 i = 0; i < members.length; i++) {
            bytes32 keyHash = keccak256(members[i].publicKey);
            if (keyHash == groupKeyHash) revert DuplicateMemberKey(i);
            for (uint256 j = 0; j < i; j++) {
                if (keyHashes[j] == keyHash) revert DuplicateMemberKey(i);
            }
            keyHashes[i] = keyHash;
        }
        for (uint256 i = 0; i < members.length; i++) {
            _admitMember(unitId, rpId, groupPublicKey, keyHashes[i], members[i]);
        }

        emit GroupCreated(unitId, keccak256(bytes(rpId)), groupKeyHash, groupPublicKey, members.length);
    }

    /// @dev The group key's content-bound authorization for the frozen
    ///      record.
    function _verifyGroup(
        string memory rpId,
        bytes memory groupPublicKey,
        Proof calldata groupProof,
        bytes32 contentHash
    ) internal view {
        (uint256 x, uint256 y) = _validatePublicKey(groupPublicKey);
        _verifyProof(groupProof, challengeFor(rpId, groupPublicKey, contentHash), rpId, x, y);
    }

    /// @dev One member joining the group being registered: resolve or
    ///      create its global entry, verify the group-scoped proof, link
    ///      membership both ways.
    function _admitMember(
        uint256 unitId,
        string memory rpId,
        bytes calldata groupPublicKey,
        bytes32 keyHash,
        Member calldata member
    ) internal {
        (uint256 x, uint256 y) = _validatePublicKey(member.publicKey);

        uint256 entryId = _resolveEntry(
            keyHash,
            member.publicKey,
            member.attestation,
            member.credentialId,
            member.authenticatorAttachment,
            member.transports
        );
        _isMemberLink[unitId][entryId] = true;
        _groupEntryIds[unitId].push(entryId);
        _entryUnitIds[entryId].push(unitId);

        bytes32 binding = memberBindingFor(groupPublicKey, member.attestation);
        _verifyProof(member.proof, challengeFor(rpId, member.publicKey, binding), rpId, x, y);

        emit MemberJoined(unitId, entryId, keyHash);
    }

    /// @dev The key's global entry id — created on first sight (fixing the
    ///      attestation forever), matched against the file after.
    function _resolveEntry(
        bytes32 keyHash,
        bytes memory publicKey,
        bytes memory attestation,
        bytes memory credentialId,
        bytes memory authenticatorAttachment,
        bytes memory transports
    ) internal returns (uint256 entryId) {
        uint256 plusOne = _entryIdPlusOneByKey[keyHash];
        if (plusOne != 0) {
            entryId = plusOne - 1;
            if (keccak256(_entries[entryId].attestation) != keccak256(attestation)) {
                revert AttestationMismatch(entryId);
            }
            if (keccak256(_entries[entryId].credentialId) != keccak256(credentialId)) {
                revert CredentialIdMismatch(entryId);
            }
            // authenticatorAttachment / transports are display hints: the
            // first write wins and later writes leave them untouched, so a
            // browser that reports them differently never blocks a re-refer.
            return entryId;
        }
        _validateAttestation(attestation);
        if (credentialId.length > MAX_CREDENTIAL_ID_LENGTH) {
            revert CredentialIdTooLong(credentialId.length);
        }
        if (authenticatorAttachment.length > MAX_AUTHENTICATOR_ATTACHMENT_LENGTH) {
            revert AuthenticatorAttachmentTooLong(authenticatorAttachment.length);
        }
        if (transports.length > MAX_TRANSPORTS_LENGTH) {
            revert TransportsTooLong(transports.length);
        }
        entryId = _entries.length;
        _entries.push(
            Entry({
                publicKey: publicKey,
                attestation: attestation,
                credentialId: credentialId,
                authenticatorAttachment: authenticatorAttachment,
                transports: transports,
                createdAt: block.timestamp
            })
        );
        _entryIdPlusOneByKey[keyHash] = entryId + 1;
        emit EntryCreated(entryId, keyHash, publicKey, attestation, credentialId);
    }

    // ── Write 2: refer a passkey to a group ────────────────────────────────

    /// @notice One passkey points at one EXISTING group: discovery data in
    ///         its own table, one reference per (group, key) pair. The
    ///         group's frozen record and indexes are untouched. The
    ///         referring key signs (group key, own attestation, reference
    ///         metadata) — so it can sign the moment it is created — and a
    ///         brand-new key gets its global entry created on the way.
    ///         References are claims, not authority: readers decide what a
    ///         referenced key means.
    function refer(
        bytes calldata groupPublicKey,
        bytes calldata metadata,
        Member calldata member
    ) external {
        _validateMetadata(metadata);

        bytes32 groupKeyHash = keccak256(groupPublicKey);
        uint256 unitPlusOne = _unitIdPlusOneByGroupKey[groupKeyHash];
        if (unitPlusOne == 0) revert GroupNotFound(groupKeyHash);
        uint256 unitId = unitPlusOne - 1;
        string memory rpId = _units[unitId].rpId;

        bytes32 keyHash = keccak256(member.publicKey);
        if (keyHash == groupKeyHash) revert DuplicateMemberKey(0);
        (uint256 x, uint256 y) = _validatePublicKey(member.publicKey);
        uint256 entryId = _resolveEntry(
            keyHash,
            member.publicKey,
            member.attestation,
            member.credentialId,
            member.authenticatorAttachment,
            member.transports
        );
        uint256 linkPlusOne = _referenceIdPlusOneByLink[unitId][entryId];
        if (linkPlusOne != 0) revert AlreadyReferenced(linkPlusOne - 1);

        bytes32 binding = referenceBindingFor(groupPublicKey, member.attestation, metadata);
        _verifyProof(member.proof, challengeFor(rpId, member.publicKey, binding), rpId, x, y);

        uint256 referenceId = _references.length;
        _references.push(
            Reference({entryId: entryId, unitId: unitId, metadata: metadata, createdAt: block.timestamp})
        );
        _referenceIdPlusOneByLink[unitId][entryId] = referenceId + 1;
        _referenceIdsByEntry[entryId].push(referenceId);
        _referenceIdsByUnit[unitId].push(referenceId);

        emit ReferenceCreated(referenceId, entryId, unitId, keyHash, groupKeyHash);
    }

    // ── Reads: passkeys ────────────────────────────────────────────────────

    /// @notice Total passkeys ever registered — entries are globally
    ///         unique, so this IS the distinct key count.
    function getTotalEntries() external view returns (uint256) {
        return _entries.length;
    }

    /// @notice One passkey's global file by its immutable id.
    function getEntry(uint256 entryId) external view returns (Entry memory) {
        if (entryId >= _entries.length) revert EntryNotFound(entryId);
        return _entries[entryId];
    }

    /// @notice Whether a public key has a file. With possession gating, at
    ///         most one of a signature's recovered candidate keys can.
    function hasEntry(bytes calldata publicKey) external view returns (bool) {
        return _entryIdPlusOneByKey[keccak256(publicKey)] != 0;
    }

    /// @notice One passkey's global file by its public key.
    function getEntryByKey(bytes calldata publicKey)
        external
        view
        returns (bool exists, uint256 entryId, Entry memory entry)
    {
        uint256 plusOne = _entryIdPlusOneByKey[keccak256(publicKey)];
        if (plusOne == 0) {
            return (false, 0, entry);
        }
        entryId = plusOne - 1;
        return (true, entryId, _entries[entryId]);
    }

    /// @notice Number of groups a passkey is a member of.
    function getTotalGroupsOfKey(bytes calldata publicKey) external view returns (uint256) {
        uint256 plusOne = _entryIdPlusOneByKey[keccak256(publicKey)];
        if (plusOne == 0) return 0;
        return _entryUnitIds[plusOne - 1].length;
    }

    /// @notice Paginated unit ids of the groups a passkey is a MEMBER of
    ///         (frozen founding memberships), in creation order.
    function getGroupsOfKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory unitIds)
    {
        uint256 plusOne = _entryIdPlusOneByKey[keccak256(publicKey)];
        if (plusOne == 0) {
            return (0, new uint256[](0));
        }
        return _pageIds(_entryUnitIds[plusOne - 1], offset, limit, desc);
    }

    // ── Reads: groups ──────────────────────────────────────────────────────

    /// @notice Total groups ever created — group keys are single-use, so
    ///         this IS the distinct group count.
    function getTotalUnits() external view returns (uint256) {
        return _units.length;
    }

    /// @notice One group's frozen record by its immutable id.
    function getUnit(uint256 unitId) external view returns (Unit memory) {
        if (unitId >= _units.length) revert UnitNotFound(unitId);
        return _units[unitId];
    }

    /// @notice One group's frozen record by its group public key — the
    ///         group's stable identity.
    function getUnitByGroupKey(bytes calldata publicKey)
        external
        view
        returns (bool exists, uint256 unitId, Unit memory unit)
    {
        uint256 plusOne = _unitIdPlusOneByGroupKey[keccak256(publicKey)];
        if (plusOne == 0) {
            return (false, 0, unit);
        }
        unitId = plusOne - 1;
        return (true, unitId, _units[unitId]);
    }

    /// @notice Resolve a group by its frozen content hash.
    function getUnitIdByContentHash(bytes32 contentHash) external view returns (bool exists, uint256 unitId) {
        uint256 plusOne = _unitIdPlusOneByContent[contentHash];
        if (plusOne == 0) return (false, 0);
        return (true, plusOne - 1);
    }

    /// @notice Whether group content has already been registered.
    function isContentRegistered(bytes32 contentHash) external view returns (bool) {
        return _unitIdPlusOneByContent[contentHash] != 0;
    }

    /// @notice Whether a passkey is a (frozen, founding) member of a group.
    function isMember(bytes calldata groupPublicKey, bytes calldata memberPublicKey) external view returns (bool) {
        uint256 unitPlusOne = _unitIdPlusOneByGroupKey[keccak256(groupPublicKey)];
        uint256 entryPlusOne = _entryIdPlusOneByKey[keccak256(memberPublicKey)];
        if (unitPlusOne == 0 || entryPlusOne == 0) return false;
        return _isMemberLink[unitPlusOne - 1][entryPlusOne - 1];
    }

    /// @notice Number of members of a group (frozen at creation).
    function getTotalGroupMembers(uint256 unitId) external view returns (uint256) {
        if (unitId >= _units.length) revert UnitNotFound(unitId);
        return _groupEntryIds[unitId].length;
    }

    /// @notice Paginated members of a group in founding order, joined with
    ///         their global files.
    function getGroupMembers(uint256 unitId, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory entryIds, Entry[] memory entries)
    {
        if (unitId >= _units.length) revert UnitNotFound(unitId);
        (total, entryIds) = _pageIds(_groupEntryIds[unitId], offset, limit, desc);
        entries = new Entry[](entryIds.length);
        for (uint256 i = 0; i < entryIds.length; i++) {
            entries[i] = _entries[entryIds[i]];
        }
    }

    // ── Reads: references ──────────────────────────────────────────────────

    /// @notice Total references ever created — counted apart from groups,
    ///         always.
    function getTotalReferences() external view returns (uint256) {
        return _references.length;
    }

    /// @notice One reference by its immutable id.
    function getReference(uint256 referenceId) external view returns (Reference memory) {
        if (referenceId >= _references.length) revert ReferenceNotFound(referenceId);
        return _references[referenceId];
    }

    /// @notice Whether a passkey holds a reference to a group.
    function isReferenced(bytes calldata groupPublicKey, bytes calldata memberPublicKey)
        external
        view
        returns (bool)
    {
        uint256 unitPlusOne = _unitIdPlusOneByGroupKey[keccak256(groupPublicKey)];
        uint256 entryPlusOne = _entryIdPlusOneByKey[keccak256(memberPublicKey)];
        if (unitPlusOne == 0 || entryPlusOne == 0) return false;
        return _referenceIdPlusOneByLink[unitPlusOne - 1][entryPlusOne - 1] != 0;
    }

    /// @notice Number of references a passkey holds.
    function getTotalReferencesOfKey(bytes calldata publicKey) external view returns (uint256) {
        uint256 plusOne = _entryIdPlusOneByKey[keccak256(publicKey)];
        if (plusOne == 0) return 0;
        return _referenceIdsByEntry[plusOne - 1].length;
    }

    /// @notice Paginated reference ids a passkey holds — the authenticated
    ///         direction: every one carries this key's own signature.
    function getReferencesOfKey(bytes calldata publicKey, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory referenceIds)
    {
        uint256 plusOne = _entryIdPlusOneByKey[keccak256(publicKey)];
        if (plusOne == 0) {
            return (0, new uint256[](0));
        }
        return _pageIds(_referenceIdsByEntry[plusOne - 1], offset, limit, desc);
    }

    /// @notice Number of references pointing at a group.
    function getTotalReferencesToGroup(bytes calldata groupPublicKey) external view returns (uint256) {
        uint256 plusOne = _unitIdPlusOneByGroupKey[keccak256(groupPublicKey)];
        if (plusOne == 0) return 0;
        return _referenceIdsByUnit[plusOne - 1].length;
    }

    /// @notice Paginated reference ids pointing at a group. COSMETIC: any
    ///         key holder can refer their own key to any group, so treat
    ///         this as a suggestion inbox, never as membership.
    function getReferencesToGroup(bytes calldata groupPublicKey, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory referenceIds)
    {
        uint256 plusOne = _unitIdPlusOneByGroupKey[keccak256(groupPublicKey)];
        if (plusOne == 0) {
            return (0, new uint256[](0));
        }
        return _pageIds(_referenceIdsByUnit[plusOne - 1], offset, limit, desc);
    }

    // ── Reads: rpId enumeration (cosmetic) ─────────────────────────────────

    /// @notice Total number of distinct rpIds.
    function getTotalRpIds() external view returns (uint256) {
        return _rpIds.length;
    }

    /// @notice Number of groups under an rpId.
    function getTotalGroupsByRpId(string calldata rpId) external view returns (uint256) {
        return _unitIdsByRpId[rpId].length;
    }

    /// @notice Paginated group ids under an rpId. Browse/stats convenience
    ///         — synthetic signers choose their own rpId, so treat
    ///         aggregate views as cosmetic.
    function getGroupsByRpId(string calldata rpId, uint256 offset, uint256 limit, bool desc)
        external
        view
        returns (uint256 total, uint256[] memory unitIds)
    {
        return _pageIds(_unitIdsByRpId[rpId], offset, limit, desc);
    }

    /// @notice Paginated list of all rpIds with group counts and first-use
    ///         times.
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
            counts[i] = _unitIdsByRpId[rp].length;
            createdAts[i] = _rpCreatedAt[rp];
        }
    }

    function _pageIds(uint256[] storage ids, uint256 offset, uint256 limit, bool desc)
        internal
        view
        returns (uint256 total, uint256[] memory page)
    {
        total = ids.length;
        if (offset >= total) {
            return (total, new uint256[](0));
        }
        uint256 remaining = total - offset;
        uint256 count = remaining < limit ? remaining : limit;
        page = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            uint256 idx = desc ? total - 1 - offset - i : offset + i;
            page[i] = ids[idx];
        }
    }
}
