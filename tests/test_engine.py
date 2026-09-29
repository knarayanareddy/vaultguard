"""Canonical serialization, hash chaining, and HMAC tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import datetime, timedelta, timezone

import pytest

from vaultguard.engine import (
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
from vaultguard.models import ZERO_HASH, AuditAction, AuditPayload, ChainBlock

SECRET_KEY = b"vaultguard-unit-test-signing-key"
OTHER_SECRET_KEY = b"a-different-vaultguard-signing-key"
UTC_TIMESTAMP = datetime(2025, 1, 15, 12, 30, 45, tzinfo=timezone.utc)


def make_payload(
    *,
    actor: str = "security-admin",
    timestamp: datetime = UTC_TIMESTAMP,
    action: AuditAction | str = AuditAction.ADMIN_OVERRIDE,
    metadata: dict[str, object] | None = None,
) -> AuditPayload:
    """Build a valid payload without sharing mutable metadata fixtures."""

    return AuditPayload(
        timestamp=timestamp,
        actor=actor,
        action=action,
        metadata=(
            {
                "reason": "incident-2025-001",
                "approved": True,
            }
            if metadata is None
            else metadata
        ),
    )


class TestCanonicalJson:
    def test_sorts_nested_keys_and_removes_whitespace(self) -> None:
        value = {
            "z": [3, 2, 1],
            "a": {
                "second": "value",
                "first": 1,
            },
        }

        assert canonical_json(value) == (
            '{"a":{"first":1,"second":"value"},"z":[3,2,1]}'
        )

    def test_uses_pydantic_json_wire_values(self) -> None:
        serialized = canonical_json(make_payload())

        assert '"action":"admin_override"' in serialized
        assert '"timestamp":"2025-01-15T12:30:45Z"' in serialized
        assert " " not in serialized

    def test_preserves_array_order(self) -> None:
        assert canonical_json({"items": [3, 1, 2]}) == '{"items":[3,1,2]}'

    def test_rejects_non_finite_numbers(self) -> None:
        with pytest.raises(ValueError):
            canonical_json({"invalid": math.nan})

    def test_rejects_unsupported_json_values(self) -> None:
        with pytest.raises(TypeError):
            canonical_json({"invalid": object()})


class TestPayloadHash:
    def test_matches_independent_sha256_calculation(self) -> None:
        payload = make_payload()
        serialized = json.dumps(
            payload.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        assert hash_payload(payload) == expected
        assert compute_payload_hash(payload) == expected

    def test_metadata_key_order_does_not_change_hash(self) -> None:
        first = make_payload(
            metadata={
                "z": {"second": 2, "first": 1},
                "a": [3, {"beta": 2, "alpha": 1}],
            }
        )
        second = make_payload(
            metadata={
                "a": [3, {"alpha": 1, "beta": 2}],
                "z": {"first": 1, "second": 2},
            }
        )

        assert hash_payload(first) == hash_payload(second)

    def test_array_order_changes_hash(self) -> None:
        first = make_payload(metadata={"values": [1, 2]})
        second = make_payload(metadata={"values": [2, 1]})

        assert hash_payload(first) != hash_payload(second)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"actor": "credential-service"},
            {"action": AuditAction.CREDENTIAL_ROTATION},
            {"timestamp": UTC_TIMESTAMP + timedelta(seconds=1)},
            {"metadata": {"approved": False}},
        ],
    )
    def test_payload_field_change_changes_hash(
        self,
        overrides: dict[str, object],
    ) -> None:
        baseline = hash_payload(make_payload())
        changed = hash_payload(make_payload(**overrides))

        assert changed != baseline

    def test_mapping_wire_value_matches_audit_payload(self) -> None:
        payload = make_payload()

        assert hash_payload(payload.model_dump(mode="json")) == hash_payload(
            payload
        )

    def test_hash_is_lowercase_sha256_hex(self) -> None:
        digest = hash_payload(make_payload())

        assert len(digest) == 64
        assert digest == digest.lower()
        assert all(character in "0123456789abcdef" for character in digest)


class TestBlockHash:
    def test_matches_independent_canonical_header_calculation(self) -> None:
        payload_hash = "1" * 64
        prev_hash = "2" * 64
        header = {
            "index": 3,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
        }
        serialized = json.dumps(
            header,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        assert compute_block_hash(3, payload_hash, prev_hash) == expected
        assert calculate_block_hash(3, payload_hash, prev_hash) == expected

    def test_parent_hash_changes_block_hash(self) -> None:
        payload_hash = hash_payload(make_payload())

        first = compute_block_hash(1, payload_hash, "2" * 64)
        second = compute_block_hash(1, payload_hash, "3" * 64)

        assert first != second

    def test_index_changes_block_hash(self) -> None:
        payload_hash = hash_payload(make_payload())

        assert compute_block_hash(1, payload_hash, "2" * 64) != (
            compute_block_hash(2, payload_hash, "2" * 64)
        )

    @pytest.mark.parametrize("index", [-1, True, 1.0, "1", None])
    def test_rejects_invalid_indices(self, index: object) -> None:
        with pytest.raises(ValueError):
            compute_block_hash(index, "1" * 64, "2" * 64)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "digest",
        [
            "",
            "1" * 63,
            "1" * 65,
            "A" * 64,
            "g" * 64,
            "1" * 63 + "g",
        ],
    )
    def test_rejects_malformed_digests(self, digest: str) -> None:
        with pytest.raises(ValueError):
            compute_block_hash(0, digest, ZERO_HASH)
        with pytest.raises(ValueError):
            compute_block_hash(0, "1" * 64, digest)


class TestHmacSignatures:
    def test_matches_independent_hmac_calculation(self) -> None:
        current_hash = "a" * 64
        expected = hmac.new(
            SECRET_KEY,
            current_hash.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

        assert generate_signature(current_hash, SECRET_KEY) == expected

    def test_accepts_equivalent_key_representations(self) -> None:
        text_key = "vaultguard-unit-test-signing-key"
        expected = generate_signature("a" * 64, text_key)

        assert generate_signature("a" * 64, text_key.encode()) == expected
        assert generate_signature(
            "a" * 64,
            bytearray(text_key.encode()),
        ) == expected
        assert generate_signature(
            "a" * 64,
            memoryview(text_key.encode()),
        ) == expected

    def test_copies_mutable_secret_key(self) -> None:
        mutable_key = bytearray(SECRET_KEY)
        digest = generate_signature("a" * 64, mutable_key)
        expected = generate_signature("a" * 64, SECRET_KEY)

        mutable_key[0] ^= 0xFF

        assert digest == expected
        assert generate_signature("a" * 64, mutable_key) != expected

    @pytest.mark.parametrize("secret_key", [b"", bytearray(), ""])
    def test_rejects_empty_secret_key(self, secret_key: object) -> None:
        with pytest.raises(ValueError):
            generate_signature("a" * 64, secret_key)  # type: ignore[arg-type]

    @pytest.mark.parametrize("secret_key", [None, 1, [], {}])
    def test_rejects_non_key_types(self, secret_key: object) -> None:
        with pytest.raises(TypeError):
            generate_signature("a" * 64, secret_key)  # type: ignore[arg-type]

    def test_verifies_valid_signature(self) -> None:
        signature = generate_signature("a" * 64, SECRET_KEY)

        assert verify_hmac_signature("a" * 64, signature, SECRET_KEY)

    def test_rejects_wrong_key(self) -> None:
        signature = generate_signature("a" * 64, SECRET_KEY)

        assert not verify_hmac_signature(
            "a" * 64,
            signature,
            OTHER_SECRET_KEY,
        )

    def test_rejects_modified_hash(self) -> None:
        signature = generate_signature("a" * 64, SECRET_KEY)

        assert not verify_hmac_signature("b" * 64, signature, SECRET_KEY)

    @pytest.mark.parametrize(
        "signature",
        ["", "4" * 63, "4" * 65, "A" * 64, "g" * 64, b"4" * 64],
    )
    def test_rejects_malformed_signature(self, signature: object) -> None:
        assert not verify_hmac_signature(
            "a" * 64,
            signature,  # type: ignore[arg-type]
            SECRET_KEY,
        )

    def test_sign_block_replaces_signature_without_changing_content(
        self,
    ) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        unsigned = genesis.model_copy(update={"signature": "0" * 64})

        signed = sign_block(unsigned, SECRET_KEY)

        assert signed.signature == generate_signature(
            signed.current_hash,
            SECRET_KEY,
        )
        assert signed.index == genesis.index
        assert signed.payload == genesis.payload
        assert signed.payload_hash == genesis.payload_hash
        assert signed.prev_hash == genesis.prev_hash
        assert signed.current_hash == genesis.current_hash

    def test_sign_block_rejects_non_block(self) -> None:
        with pytest.raises(TypeError):
            sign_block(object(), SECRET_KEY)  # type: ignore[arg-type]

    def test_verify_block_signature_validates_hmac_only(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)

        assert verify_block_signature(genesis, SECRET_KEY)
        assert not verify_block_signature(genesis, OTHER_SECRET_KEY)
        assert not verify_block_signature(object(), SECRET_KEY)  # type: ignore[arg-type]


class TestBlockConstruction:
    def test_creates_genesis_block_with_zero_parent(self) -> None:
        payload = make_payload()

        genesis = create_genesis_block(payload, SECRET_KEY)

        assert genesis.index == 0
        assert genesis.prev_hash == ZERO_HASH
        assert genesis.payload == payload
        assert genesis.payload_hash == hash_payload(payload)
        assert genesis.current_hash == compute_block_hash(
            0,
            genesis.payload_hash,
            ZERO_HASH,
        )
        assert genesis.signature == generate_signature(
            genesis.current_hash,
            SECRET_KEY,
        )
        assert verify_block(genesis, SECRET_KEY)

    def test_creates_next_block_from_valid_parent(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        next_payload = make_payload(
            actor="credential-service",
            action=AuditAction.CREDENTIAL_ROTATION,
        )

        next_block = create_next_block(
            genesis,
            next_payload,
            SECRET_KEY,
        )

        assert next_block.index == 1
        assert next_block.prev_hash == genesis.current_hash
        assert next_block.payload == next_payload
        assert next_block.payload_hash == hash_payload(next_payload)
        assert next_block.current_hash == compute_block_hash(
            1,
            next_block.payload_hash,
            genesis.current_hash,
        )
        assert next_block.signature == generate_signature(
            next_block.current_hash,
            SECRET_KEY,
        )
        assert verify_block(next_block, SECRET_KEY, previous_block=genesis)

    def test_creates_explicit_non_genesis_block(self) -> None:
        payload = make_payload()
        parent_hash = "2" * 64

        block = create_block(1, payload, parent_hash, SECRET_KEY)

        assert block.prev_hash == parent_hash
        assert block.payload_hash == hash_payload(payload)
        assert verify_block(block, SECRET_KEY)

    def test_rejects_parent_signed_with_another_key(self) -> None:
        genesis = create_genesis_block(make_payload(), OTHER_SECRET_KEY)

        with pytest.raises(ValueError, match="valid parent"):
            create_next_block(
                genesis,
                make_payload(),
                SECRET_KEY,
            )

    def test_rejects_non_chain_parent(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        invalid_parent = genesis.model_copy(
            update={"current_hash": "f" * 64}
        )

        with pytest.raises(ValueError, match="valid parent"):
            create_next_block(
                invalid_parent,
                make_payload(),
                SECRET_KEY,
            )

    def test_rejects_invalid_parent_type(self) -> None:
        with pytest.raises(TypeError, match="previous_block"):
            create_next_block(
                object(),  # type: ignore[arg-type]
                make_payload(),
                SECRET_KEY,
            )

    def test_rejects_invalid_payload_type(self) -> None:
        with pytest.raises(TypeError, match="payload"):
            create_block(
                0,
                {"actor": "admin"},  # type: ignore[arg-type]
                ZERO_HASH,
                SECRET_KEY,
            )

    def test_enforces_genesis_link_shape(self) -> None:
        with pytest.raises(ValueError, match="genesis"):
            create_block(
                0,
                make_payload(),
                "1" * 64,
                SECRET_KEY,
            )

    def test_enforces_non_genesis_link_shape(self) -> None:
        with pytest.raises(ValueError, match="parent"):
            create_block(
                1,
                make_payload(),
                ZERO_HASH,
                SECRET_KEY,
            )


class TestBlockVerification:
    def test_detects_modified_payload(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        modified = genesis.model_copy(
            update={"payload": make_payload(actor="attacker")}
        )

        assert not verify_block(modified, SECRET_KEY)

    def test_detects_modified_timestamp(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        modified = genesis.model_copy(
            update={
                "payload": make_payload(
                    timestamp=UTC_TIMESTAMP + timedelta(seconds=1)
                )
            }
        )

        assert not verify_block(modified, SECRET_KEY)

    def test_detects_modified_payload_hash(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        modified = genesis.model_copy(
            update={"payload_hash": "f" * 64}
        )

        assert not verify_block(modified, SECRET_KEY)

    def test_detects_modified_current_hash(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        modified = genesis.model_copy(
            update={"current_hash": "f" * 64}
        )

        assert not verify_block(modified, SECRET_KEY)

    def test_detects_modified_signature(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        modified = genesis.model_copy(
            update={"signature": "f" * 64}
        )

        assert not verify_block(modified, SECRET_KEY)

    def test_detects_wrong_parent_link(self) -> None:
        first_genesis = create_genesis_block(make_payload(), SECRET_KEY)
        second_genesis = create_genesis_block(
            make_payload(actor="another-admin"),
            SECRET_KEY,
        )
        child = create_next_block(
            first_genesis,
            make_payload(action=AuditAction.READ),
            SECRET_KEY,
        )

        assert not verify_block(
            child,
            SECRET_KEY,
            previous_block=second_genesis,
        )

    def test_rejects_nonconsecutive_parent(self) -> None:
        genesis = create_genesis_block(make_payload(), SECRET_KEY)
        child = create_next_block(
            genesis,
            make_payload(action=AuditAction.READ),
            SECRET_KEY,
        )
        grandchild = create_next_block(
            child,
            make_payload(action=AuditAction.UPDATE),
            SECRET_KEY,
        )

        assert not verify_block(
            grandchild,
            SECRET_KEY,
            previous_block=genesis,
        )

    def test_returns_false_for_non_block(self) -> None:
        assert not verify_block(object(), SECRET_KEY)  # type: ignore[arg-type]


class TestHashChainEngine:
    def test_delegates_canonicalization_and_hash_operations(self) -> None:
        engine = HashChainEngine(SECRET_KEY)
        payload = make_payload()
        payload_hash = hash_payload(payload)
        previous_hash = "2" * 64
        current_hash = compute_block_hash(1, payload_hash, previous_hash)
        signature = engine.generate_signature(current_hash)

        assert engine.canonical_json(payload) == canonical_json(payload)
        assert engine.hash_payload(payload) == payload_hash
        assert engine.compute_payload_hash(payload) == payload_hash
        assert engine.compute_block_hash(
            1,
            payload_hash,
            previous_hash,
        ) == current_hash
        assert engine.calculate_block_hash(
            1,
            payload_hash,
            previous_hash,
        ) == current_hash
        assert engine.verify_hmac_signature(
            current_hash,
            signature,
            SECRET_KEY,
        )

    def test_creates_signs_and_verifies_a_chain(self) -> None:
        engine = HashChainEngine(SECRET_KEY)
        first_payload = make_payload()
        second_payload = make_payload(
            actor="credential-service",
            action=AuditAction.CREDENTIAL_ROTATION,
        )

        genesis = engine.create_genesis_block(first_payload)
        child = engine.create_next_block(genesis, second_payload)
        explicit = engine.create_block(
            2,
            make_payload(action=AuditAction.UPDATE),
            child.current_hash,
        )
        resigned = engine.sign_block(
            explicit.model_copy(update={"signature": "0" * 64})
        )

        assert engine.verify_block(genesis)
        assert engine.verify_block(child, previous_block=genesis)
        assert engine.verify_block(explicit, previous_block=child)
        assert engine.verify_block(resigned, previous_block=child)
        assert engine.verify_block_signature(resigned)
        assert not engine.verify_block(
            resigned,
            previous_block=genesis,
        )

    def test_mutating_original_key_does_not_change_engine_key(self) -> None:
        mutable_key = bytearray(SECRET_KEY)
        engine = HashChainEngine(mutable_key)

        mutable_key[0] ^= 0xFF
        genesis = engine.create_genesis_block(make_payload())

        assert genesis.signature == generate_signature(
            genesis.current_hash,
            SECRET_KEY,
        )
        assert engine.verify_block(genesis)

    @pytest.mark.parametrize("secret_key", [None, 1, [], {}])
    def test_rejects_invalid_constructor_key(self, secret_key: object) -> None:
        with pytest.raises(TypeError):
            HashChainEngine(secret_key)  # type: ignore[arg-type]

    def test_rejects_empty_constructor_key(self) -> None:
        with pytest.raises(ValueError):
            HashChainEngine(b"")