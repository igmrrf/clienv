// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title BsecSecretRegistry
 * @dev Decentralized, tamper-proof registry for ephemeral secret sharing on EVM blockchains.
 * Encrypted secret payloads are stored on IPFS, while access controls, expiration timestamps,
 * read limits, and sender identities (msg.sender) are immutably verified on-chain.
 */
contract BsecSecretRegistry {
    struct SecretRecord {
        address sender;          // Verified sender address (msg.sender)
        address recipient;       // Recipient address (0x0 for public secrets)
        string ipfsCid;          // IPFS CID containing AES-256-GCM + ECDH payload
        uint64 createdAt;        // Timestamp of creation
        uint64 expiresAt;        // Expiration timestamp
        uint32 maxReads;         // Maximum read limit
        uint32 readCount;        // Current read count
        bool revoked;            // Revocation status
        bool isPublic;           // Public secret indicator
    }

    // Mapping from unique secret ID (bytes32) to SecretRecord
    mapping(bytes32 => SecretRecord) private _secrets;

    // Events
    event SecretShared(
        bytes32 indexed secretId,
        address indexed sender,
        address indexed recipient,
        string ipfsCid,
        uint64 expiresAt,
        uint32 maxReads,
        bool isPublic
    );

    event SecretViewed(
        bytes32 indexed secretId,
        address indexed viewer,
        uint32 readCount,
        uint32 maxReads
    );

    event SecretRevoked(
        bytes32 indexed secretId,
        address indexed sender
    );

    // Custom Errors
    error SecretAlreadyExists(bytes32 secretId);
    error SecretNotFound(bytes32 secretId);
    error SecretExpired(bytes32 secretId, uint64 expiresAt, uint64 currentTime);
    error ReadLimitExceeded(bytes32 secretId, uint32 readCount, uint32 maxReads);
    error SecretIsRevoked(bytes32 secretId);
    error UnauthorizedViewer(bytes32 secretId, address viewer);
    error UnauthorizedRevoker(bytes32 secretId, address caller);
    error InvalidParameters();

    /**
     * @dev Shares a new encrypted secret by registering its IPFS CID and access rules on-chain.
     */
    function shareSecret(
        bytes32 secretId,
        address recipient,
        string calldata ipfsCid,
        uint64 expiresAt,
        uint32 maxReads,
        bool isPublic
    ) external {
        if (secretId == bytes32(0) || bytes(ipfsCid).length == 0) revert InvalidParameters();
        if (_secrets[secretId].sender != address(0)) revert SecretAlreadyExists(secretId);
        if (expiresAt <= block.timestamp) revert InvalidParameters();

        _secrets[secretId] = SecretRecord({
            sender: msg.sender,
            recipient: recipient,
            ipfsCid: ipfsCid,
            createdAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            maxReads: maxReads,
            readCount: 0,
            revoked: false,
            isPublic: isPublic
        });

        emit SecretShared(
            secretId,
            msg.sender,
            recipient,
            ipfsCid,
            expiresAt,
            maxReads,
            isPublic
        );
    }

    /**
     * @dev Increments the read count when an authorized user accesses a secret.
     */
    function recordRead(bytes32 secretId) external {
        SecretRecord storage record = _secrets[secretId];
        if (record.sender == address(0)) revert SecretNotFound(secretId);
        if (record.revoked) revert SecretIsRevoked(secretId);
        if (block.timestamp > record.expiresAt) revert SecretExpired(secretId, record.expiresAt, uint64(block.timestamp));

        // Public secrets are readable by anyone and are NOT read-limited: enforcing maxReads
        // here would let any caller burn the limit and deny legitimate readers (griefing).
        // Read limits and viewer authorization apply only to non-public secrets.
        if (!record.isPublic) {
            if (record.readCount >= record.maxReads) {
                revert ReadLimitExceeded(secretId, record.readCount, record.maxReads);
            }
            if (msg.sender != record.recipient && msg.sender != record.sender) {
                revert UnauthorizedViewer(secretId, msg.sender);
            }
        }

        record.readCount += 1;

        emit SecretViewed(secretId, msg.sender, record.readCount, record.maxReads);
    }

    /**
     * @dev Revokes a shared secret immediately. Only the original sender (msg.sender) can revoke.
     */
    function revokeSecret(bytes32 secretId) external {
        SecretRecord storage record = _secrets[secretId];
        if (record.sender == address(0)) revert SecretNotFound(secretId);
        if (record.sender != msg.sender) revert UnauthorizedRevoker(secretId, msg.sender);
        if (record.revoked) revert SecretIsRevoked(secretId);

        record.revoked = true;

        emit SecretRevoked(secretId, msg.sender);
    }

    /**
     * @dev Retrieves details of a secret record.
     */
    function getSecretInfo(bytes32 secretId) external view returns (
        address sender,
        address recipient,
        string memory ipfsCid,
        uint64 createdAt,
        uint64 expiresAt,
        uint32 maxReads,
        uint32 readCount,
        bool revoked,
        bool isPublic,
        bool isExpired,
        bool limitReached
    ) {
        SecretRecord memory record = _secrets[secretId];
        if (record.sender == address(0)) revert SecretNotFound(secretId);

        bool expired = block.timestamp > record.expiresAt;
        // Public secrets are not read-limited (see recordRead).
        bool limitExceeded = !record.isPublic && record.readCount >= record.maxReads;

        return (
            record.sender,
            record.recipient,
            record.ipfsCid,
            record.createdAt,
            record.expiresAt,
            record.maxReads,
            record.readCount,
            record.revoked,
            record.isPublic,
            expired,
            limitExceeded
        );
    }
}
