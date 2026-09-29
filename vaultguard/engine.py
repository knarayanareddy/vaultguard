"""Canonical serialization and cryptographic primitives for VaultGuard.

The payload is serialized deterministically and hashed with SHA-256. Each
block digest commits to the block index, payload digest, and preceding block
digest. The resulting block digest is authenticated with HMAC-SHA256.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from typing import Final, TypeAlias

from pydantic import BaseModel

from .models import ZERO_HASH, AuditPayload, ChainBlock

PayloadSource: TypeAlias = AuditPayload | Mapping[str, object]
SecretKey: TypeAlias = bytes | bytearray | memoryview | str

_SHA256_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{64}$"
)

__all__ = [
    "HashChainEngine",
    "PayloadSource",
    "SecretKey",
    "calculate_block_hash",
    "canonical_json",
    "compute_block_hash",
    "compute_payload_hash",
    "create_block",
    "create_genesis_block",
    "create_next_block",
    "generate_signature",
    "hash_payload",
    "sign_block",
    "verify_block",
    "verify_block_signature",
    "verify_hmac_signature",
]


def canonical_json(value: object) -> str:
    """Return VaultGuard's deterministic JSON representation.

    Pydantic models are converted to their JSON-mode representation before
    serialization. Object keys are sorted recursively, insignificant
    whitespace is removed, non-ASCII characters are represented with JSON
    escapes, and non-finite floating-point values are rejected.
    """

    json_value = (
        value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    )
    return json.dumps(
        json_value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_bytes(value: object) -> bytes:
    """Return the canonical UTF-8 representation used for hashing."""

    return canonical_json(value).encode("utf-8")


def hash_payload(payload: PayloadSource) -> str:
    """Compute the canonical SHA-256 digest of an audit payload."""

    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def compute_payload_hash(payload: PayloadSource) -> str:
    """Compute a payload digest using the public engine API name."""

    return hash_payload(payload)


def _require_sha256(value: object, *, field_name: str) -> str:
    """Validate and return a lowercase hexadecimal SHA-256 digest."""

    if not isinstance(value, str) or _SHA256_HEX_PATTERN.fullmatch(value) is None:
        raise ValueError(
            f"{field_name} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def _coerce_secret_key(secret_key: SecretKey) -> bytes:
    """Copy an HMAC secret into immutable bytes and reject empty keys."""

    if isinstance(secret_key, str):
        key = secret_key.encode("utf-8")
    elif isinstance(secret_key, (bytes, bytearray, memoryview)):
        key = bytes(secret_key)
    else:
        raise TypeError("secret_key must be str or bytes-like")

    if not key:
        raise ValueError("secret_key must not be empty")

    return key


def compute_block_hash(
    index: int,
    payload_hash: str,
    prev_hash: str,
) -> str:
    """Compute a block digest from its immutable chain header.

    The canonical header contains exactly the block index, payload digest,
    and preceding block digest. The payload itself is committed through
    ``payload_hash``.
    """

    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("index must be a non-negative integer")

    normalized_payload_hash = _require_sha256(
        payload_hash,
        field_name="payload_hash",
    )
    normalized_prev_hash = _require_sha256(
        prev_hash,
        field_name="prev_hash",
    )

    return hash_payload(
        {
            "index": index,
            "payload_hash": normalized_payload_hash,
            "prev_hash": normalized_prev_hash,
        }
    )


def calculate_block_hash(
    index: int,
    payload_hash: str,
    prev_hash: str,
) -> str:
    """Compatibility name for :func:`compute_block_hash`."""

    return compute_block_hash(index, payload_hash, prev_hash)


def generate_signature(current_hash: str, secret_key: SecretKey) -> str:
    """Authenticate a block digest with HMAC-SHA256.

    HMAC authenticates the hexadecimal block digest, which in turn commits to
    the block index, canonical payload digest, and entire parent chain.
    """

    normalized_hash = _require_sha256(
        current_hash,
        field_name="current_hash",
    )
    key = _coerce_secret_key(secret_key)

    return hmac.new(
        key,
        normalized_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac_signature(
    current_hash: str,
    signature: str,
    secret_key: SecretKey,
) -> bool:
    """Return whether ``signature`` authenticates ``current_hash``.

    Malformed digest or signature strings produce ``False``. An invalid
    secret-key type or an empty key remains a caller/configuration error and
    raises an exception.
    """

    try:
        normalized_hash = _require_sha256(
            current_hash,
            field_name="current_hash",
        )
        normalized_signature = _require_sha256(
            signature,
            field_name="signature",
        )
    except ValueError:
        return False

    key = _coerce_secret_key(secret_key)
    expected_signature = hmac.new(
        key,
        normalized_hash.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_signature, normalized_signature)


def sign_block(block: ChainBlock, secret_key: SecretKey) -> ChainBlock:
    """Return a copy of ``block`` carrying a freshly generated signature."""

    if not isinstance(block, ChainBlock):
        raise TypeError("block must be a ChainBlock")

    return ChainBlock(
        index=block.index,
        payload=block.payload,
        payload_hash=block.payload_hash,
        prev_hash=block.prev_hash,
        current_hash=block.current_hash,
        signature=generate_signature(block.current_hash, secret_key),
    )


def verify_block_signature(
    block: ChainBlock,
    secret_key: SecretKey,
) -> bool:
    """Return whether a block's stored HMAC is valid."""

    if not isinstance(block, ChainBlock):
        return False

    return verify_hmac_signature(
        block.current_hash,
        block.signature,
        secret_key,
    )


def verify_block(
    block: ChainBlock,
    secret_key: SecretKey,
    *,
    previous_block: ChainBlock | None = None,
) -> bool:
    """Verify a block's intrinsic cryptographic integrity.

    This verifies the genesis/non-genesis link shape, payload digest, block
    digest, and HMAC. If ``previous_block`` is supplied, its cryptographic
    integrity and direct link to ``block`` are verified as well. Verification
    of the complete ancestry is performed by the storage-layer chain traversal.
    """

    if not isinstance(block, ChainBlock):
        return False

    if block.index == 0:
        if block.prev_hash != ZERO_HASH:
            return False
    elif block.prev_hash == ZERO_HASH:
        return False

    if previous_block is not None:
        if not isinstance(previous_block, ChainBlock):
            return False
        if previous_block.index + 1 != block.index:
            return False
        if previous_block.current_hash != block.prev_hash:
            return False
        if not verify_block(previous_block, secret_key):
            return False

    try:
        calculated_payload_hash = compute_payload_hash(block.payload)
        if not hmac.compare_digest(
            calculated_payload_hash,
            block.payload_hash,
        ):
            return False

        calculated_current_hash = compute_block_hash(
            block.index,
            block.payload_hash,
            block.prev_hash,
        )
        if not hmac.compare_digest(
            calculated_current_hash,
            block.current_hash,
        ):
            return False
    except (TypeError, ValueError):
        return False

    return verify_block_signature(block, secret_key)


def create_block(
    index: int,
    payload: AuditPayload,
    prev_hash: str,
    secret_key: SecretKey,
) -> ChainBlock:
    """Construct and sign a block at an explicit chain position."""

    if not isinstance(payload, AuditPayload):
        raise TypeError("payload must be an AuditPayload")

    normalized_prev_hash = _require_sha256(
        prev_hash,
        field_name="prev_hash",
    )

    if index == 0 and normalized_prev_hash != ZERO_HASH:
        raise ValueError("the genesis block prev_hash must be the zero hash")
    if index > 0 and normalized_prev_hash == ZERO_HASH:
        raise ValueError("non-genesis blocks must reference a parent hash")

    payload_hash = compute_payload_hash(payload)
    current_hash = compute_block_hash(
        index,
        payload_hash,
        normalized_prev_hash,
    )
    signature = generate_signature(current_hash, secret_key)

    return ChainBlock(
        index=index,
        payload=payload,
        payload_hash=payload_hash,
        prev_hash=normalized_prev_hash,
        current_hash=current_hash,
        signature=signature,
    )


def create_genesis_block(
    payload: AuditPayload,
    secret_key: SecretKey,
) -> ChainBlock:
    """Create the signed block at index zero."""

    return create_block(
        index=0,
        payload=payload,
        prev_hash=ZERO_HASH,
        secret_key=secret_key,
    )


def create_next_block(
    previous_block: ChainBlock,
    payload: AuditPayload,
    secret_key: SecretKey,
) -> ChainBlock:
    """Create a signed child of a cryptographically valid parent block."""

    if not isinstance(previous_block, ChainBlock):
        raise TypeError("previous_block must be a ChainBlock")

    if not verify_block(previous_block, secret_key):
        raise ValueError("previous_block is not a cryptographically valid parent")

    return create_block(
        index=previous_block.index + 1,
        payload=payload,
        prev_hash=previous_block.current_hash,
        secret_key=secret_key,
    )


class HashChainEngine:
    """Reusable facade for creating and verifying signed hash-chain blocks.

    The supplied secret is copied and retained as immutable bytes, preventing
    caller mutation of a ``bytearray`` or ``memoryview`` from changing the key
    used by an existing engine instance.
    """

    __slots__ = ("_secret_key",)

    def __init__(self, secret_key: SecretKey) -> None:
        self._secret_key = _coerce_secret_key(secret_key)

    @staticmethod
    def canonical_json(value: object) -> str:
        """Return canonical JSON for a JSON-compatible value."""

        return canonical_json(value)

    @staticmethod
    def hash_payload(payload: PayloadSource) -> str:
        """Compute a payload digest."""

        return hash_payload(payload)

    @staticmethod
    def compute_payload_hash(payload: PayloadSource) -> str:
        """Compute a payload digest using the explicit API name."""

        return compute_payload_hash(payload)

    @staticmethod
    def compute_block_hash(
        index: int,
        payload_hash: str,
        prev_hash: str,
    ) -> str:
        """Compute a block digest."""

        return compute_block_hash(index, payload_hash, prev_hash)

    @staticmethod
    def calculate_block_hash(
        index: int,
        payload_hash: str,
        prev_hash: str,
    ) -> str:
        """Compute a block digest using the compatibility API name."""

        return calculate_block_hash(index, payload_hash, prev_hash)

    def generate_signature(self, current_hash: str) -> str:
        """Generate an HMAC for a block digest."""

        return generate_signature(current_hash, self._secret_key)

    @staticmethod
    def verify_hmac_signature(
        current_hash: str,
        signature: str,
        secret_key: SecretKey,
    ) -> bool:
        """Verify an HMAC using an explicitly supplied key."""

        return verify_hmac_signature(current_hash, signature, secret_key)

    def sign_block(self, block: ChainBlock) -> ChainBlock:
        """Return a signed copy of a block."""

        return sign_block(block, self._secret_key)

    def verify_block_signature(self, block: ChainBlock) -> bool:
        """Verify a block signature with this engine's key."""

        return verify_block_signature(block, self._secret_key)

    def verify_block(
        self,
        block: ChainBlock,
        *,
        previous_block: ChainBlock | None = None,
    ) -> bool:
        """Verify a block with this engine's key."""

        return verify_block(
            block,
            self._secret_key,
            previous_block=previous_block,
        )

    def create_block(
        self,
        index: int,
        payload: AuditPayload,
        prev_hash: str,
    ) -> ChainBlock:
        """Construct a signed block with this engine's key."""

        return create_block(
            index,
            payload,
            prev_hash,
            self._secret_key,
        )

    def create_genesis_block(self, payload: AuditPayload) -> ChainBlock:
        """Construct a signed genesis block with this engine's key."""

        return create_genesis_block(payload, self._secret_key)

    def create_next_block(
        self,
        previous_block: ChainBlock,
        payload: AuditPayload,
    ) -> ChainBlock:
        """Construct a signed child block with this engine's key."""

        return create_next_block(
            previous_block,
            payload,
            self._secret_key,
        )