"""Public domain API for VaultGuard."""

from .engine import (
    HashChainEngine,
    calculate_block_hash,
    canonical_json,
    compute_block_hash,
    compute_payload_hash,
    create_block,
    create_genesis_block,
    create_next_block,
    generate_signature,
    hash_payload,
    sign_block,
    verify_block,
    verify_block_signature,
    verify_hmac_signature,
)
from .models import (
    ZERO_HASH,
    AuditAction,
    AuditPayload,
    ChainBlock,
    VerificationResult,
)

__all__ = [
    "ZERO_HASH",
    "AuditAction",
    "AuditPayload",
    "ChainBlock",
    "HashChainEngine",
    "VerificationResult",
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