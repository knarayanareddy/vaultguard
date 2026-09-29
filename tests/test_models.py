"""Validation, serialization, and immutability tests for domain models."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum

import pytest
from pydantic import ValidationError

from vaultguard.models import (
    ZERO_HASH,
    AuditAction,
    AuditPayload,
    ChainBlock,
    VerificationResult,
)

UTC_TIMESTAMP = datetime(2025, 1, 15, 12, 30, 45, tzinfo=timezone.utc)
PAYLOAD_HASH = "1" * 64
PREVIOUS_HASH = "2" * 64
CURRENT_HASH = "3" * 64
SIGNATURE = "4" * 64


def make_payload(**overrides: object) -> AuditPayload:
    values: dict[str, object] = {
        "timestamp": UTC_TIMESTAMP,
        "actor": "security-admin",
        "action": AuditAction.ADMIN_OVERRIDE,
        "metadata": {
            "reason": "incident-2025-001",
            "approved": True,
        },
    }
    values.update(overrides)
    return AuditPayload(**values)


def make_genesis_block(**overrides: object) -> ChainBlock:
    values: dict[str, object] = {
        "index": 0,
        "payload": make_payload(),
        "payload_hash": PAYLOAD_HASH,
        "prev_hash": ZERO_HASH,
        "current_hash": CURRENT_HASH,
        "signature": SIGNATURE,
    }
    values.update(overrides)
    return ChainBlock(**values)


def make_next_block(**overrides: object) -> ChainBlock:
    values: dict[str, object] = {
        "index": 1,
        "payload": make_payload(),
        "payload_hash": PAYLOAD_HASH,
        "prev_hash": PREVIOUS_HASH,
        "current_hash": CURRENT_HASH,
        "signature": SIGNATURE,
    }
    values.update(overrides)
    return ChainBlock(**values)


class TestAuditAction:
    def test_action_members_have_stable_wire_values(self) -> None:
        assert issubclass(AuditAction, Enum)
        assert {action.value for action in AuditAction} == {
            "login",
            "logout",
            "create",
            "read",
            "update",
            "delete",
            "admin_override",
            "credential_rotation",
            "database_migration",
        }
        assert all(isinstance(action.value, str) for action in AuditAction)

    def test_unknown_action_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            AuditAction("arbitrary_unknown_action")

    def test_payload_accepts_known_action_wire_string(self) -> None:
        assert make_payload(action="login").action is AuditAction.LOGIN

    @pytest.mark.parametrize("invalid", [1, True, None, b"login", ["login"]])
    def test_payload_rejects_non_string_action_values(self, invalid: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(action=invalid)

    def test_payload_rejects_unknown_action(self) -> None:
        with pytest.raises(ValidationError):
            make_payload(action="arbitrary_unknown_action")


class TestAuditPayload:
    def test_accepts_valid_payload(self) -> None:
        payload = make_payload()

        assert payload.timestamp == UTC_TIMESTAMP
        assert payload.timestamp.tzinfo is timezone.utc
        assert payload.actor == "security-admin"
        assert payload.action is AuditAction.ADMIN_OVERRIDE
        assert payload.metadata["approved"] is True

    @pytest.mark.parametrize(
        "timestamp",
        [
            "2025-01-15T12:30:45Z",
            "2025-01-15T12:30:45+00:00",
            "2025-01-15T12:30:45.123456Z",
        ],
    )
    def test_accepts_explicit_utc_iso_timestamps(self, timestamp: str) -> None:
        assert make_payload(timestamp=timestamp).timestamp.tzinfo is timezone.utc

    @pytest.mark.parametrize(
        "timestamp",
        [
            datetime(2025, 1, 15, 12, 30, 45),
            "2025-01-15T12:30:45",
            "2025-01-15",
            "not-a-timestamp",
        ],
    )
    def test_rejects_naive_or_invalid_timestamps(self, timestamp: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(timestamp=timestamp)

    @pytest.mark.parametrize(
        "timestamp",
        [
            datetime(
                2025,
                1,
                15,
                12,
                30,
                45,
                tzinfo=timezone(timedelta(hours=1)),
            ),
            "2025-01-15T12:30:45+01:00",
        ],
    )
    def test_rejects_non_utc_timestamps(self, timestamp: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(timestamp=timestamp)

    @pytest.mark.parametrize(
        "actor",
        [
            "",
            " ",
            " admin",
            "admin ",
            "admin\n",
            "admin\u2028",
            "\u200badmin",
        ],
    )
    def test_rejects_unsafe_actor_identifiers(self, actor: str) -> None:
        with pytest.raises(ValidationError):
            make_payload(actor=actor)

    def test_enforces_actor_length_boundary(self) -> None:
        assert len(make_payload(actor="a" * 256).actor) == 256
        with pytest.raises(ValidationError):
            make_payload(actor="a" * 257)

    def test_metadata_defaults_to_a_new_empty_object(self) -> None:
        first = make_payload(metadata={})
        second = make_payload(metadata={})

        first.metadata["key"] = "value"
        assert second.metadata == {}

    def test_accepts_nested_json_metadata(self) -> None:
        metadata = {
            "resources": ["database", {"name": "vault", "replicas": 3}],
            "approved": True,
            "score": 99.5,
            "optional": None,
        }

        assert make_payload(metadata=metadata).metadata == metadata

    @pytest.mark.parametrize("metadata", [[], (), "metadata", 1, True, None])
    def test_metadata_must_be_an_object(self, metadata: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(metadata=metadata)

    @pytest.mark.parametrize(
        "value",
        [b"bytes", Decimal("1.23"), datetime.now(), {1: "integer key"}],
    )
    def test_metadata_rejects_non_json_values(self, value: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(metadata={"value": value})

    @pytest.mark.parametrize(
        "value",
        [math.nan, math.inf, -math.inf, [1.0, math.nan], {"nested": math.inf}],
    )
    def test_metadata_rejects_non_finite_numbers(self, value: object) -> None:
        with pytest.raises(ValidationError):
            make_payload(metadata={"value": value})

    def test_metadata_rejects_recursive_containers(self) -> None:
        metadata: dict[str, object] = {}
        metadata["self"] = metadata

        with pytest.raises(ValidationError):
            make_payload(metadata=metadata)

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            AuditPayload(
                timestamp=UTC_TIMESTAMP,
                actor="security-admin",
                action=AuditAction.LOGIN,
                metadata={},
                unexpected=True,
            )

    def test_json_round_trip_preserves_payload(self) -> None:
        payload = make_payload()

        restored = AuditPayload.model_validate_json(payload.model_dump_json())

        assert restored == payload
        assert restored.action is AuditAction.ADMIN_OVERRIDE

    def test_fields_are_immutable(self) -> None:
        payload = make_payload()

        with pytest.raises(ValidationError):
            payload.actor = "another-actor"  # type: ignore[misc]


class TestChainBlock:
    def test_accepts_genesis_block(self) -> None:
        block = make_genesis_block()

        assert block.index == 0
        assert block.prev_hash == ZERO_HASH
        assert block.payload == make_payload()

    def test_accepts_non_genesis_block(self) -> None:
        assert make_next_block().index == 1

    def test_genesis_requires_zero_previous_hash(self) -> None:
        with pytest.raises(ValidationError):
            make_genesis_block(prev_hash=PREVIOUS_HASH)

    def test_non_genesis_cannot_use_genesis_previous_hash(self) -> None:
        with pytest.raises(ValidationError):
            make_next_block(prev_hash=ZERO_HASH)

    @pytest.mark.parametrize("index", [-1, 1.0, True, None, "0"])
    def test_index_is_strict_nonnegative_integer(self, index: object) -> None:
        with pytest.raises(ValidationError):
            make_genesis_block(index=index)

    def test_payload_must_be_instance_in_python_mode(self) -> None:
        values = make_genesis_block().model_dump()
        values["payload"] = make_payload().model_dump()

        with pytest.raises(
            ValidationError,
            match="payload must be an AuditPayload instance",
        ):
            ChainBlock.model_validate(values)

    def test_payload_object_is_hydrated_from_json(self) -> None:
        block = make_genesis_block()

        restored = ChainBlock.model_validate_json(block.model_dump_json())

        assert restored == block
        assert isinstance(restored.payload, AuditPayload)

    def test_payload_json_must_still_be_valid(self) -> None:
        values = make_genesis_block().model_dump(mode="json")
        values["payload"]["actor"] = 123

        with pytest.raises(ValidationError):
            ChainBlock.model_validate_json(values)

    @pytest.mark.parametrize(
        "field_name",
        ["payload_hash", "prev_hash", "current_hash", "signature"],
    )
    def test_hashes_are_strict_lowercase_sha256_hex(self, field_name: str) -> None:
        for invalid in (1, None, "A" * 64, "f" * 63, "f" * 65, "g" * 64):
            with pytest.raises(ValidationError):
                make_genesis_block(**{field_name: invalid})

    def test_rejects_unknown_block_fields(self) -> None:
        values = make_genesis_block().model_dump()
        values["unexpected"] = "value"

        with pytest.raises(ValidationError):
            ChainBlock.model_validate(values)

    def test_block_fields_are_immutable(self) -> None:
        block = make_genesis_block()

        with pytest.raises(ValidationError):
            block.current_hash = "f" * 64  # type: ignore[misc]


class TestVerificationResult:
    def test_valid_result_has_no_violation_by_default(self) -> None:
        result = VerificationResult(
            is_valid=True,
            total_blocks=3,
            message="Chain integrity verified",
        )

        assert result.violation_index is None

    def test_invalid_result_identifies_violation(self) -> None:
        result = VerificationResult(
            is_valid=False,
            total_blocks=3,
            violation_index=2,
            message="Block hash mismatch",
        )

        assert result.violation_index == 2

    @pytest.mark.parametrize("is_valid", [0, 1, "true", None, []])
    def test_is_valid_is_strict_boolean(self, is_valid: object) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=is_valid,
                total_blocks=0,
                message="message",
            )

    @pytest.mark.parametrize("total_blocks", [-1, True, 1.0, None, "1"])
    def test_total_blocks_is_strict_nonnegative_integer(
        self,
        total_blocks: object,
    ) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=True,
                total_blocks=total_blocks,
                message="message",
            )

    @pytest.mark.parametrize("violation_index", [-1, True, 1.0, None, "0"])
    def test_violation_index_is_strict_nonnegative_integer(
        self,
        violation_index: object,
    ) -> None:
        values: dict[str, object] = {
            "is_valid": False,
            "total_blocks": 2,
            "message": "message",
        }
        if violation_index is not None:
            values["violation_index"] = violation_index

        if violation_index is None:
            with pytest.raises(ValidationError):
                VerificationResult(**values)
        else:
            with pytest.raises(ValidationError):
                VerificationResult(**values)

    def test_violation_index_must_be_within_chain(self) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=False,
                total_blocks=2,
                violation_index=2,
                message="message",
            )

    def test_valid_result_rejects_violation_index(self) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=True,
                total_blocks=2,
                violation_index=0,
                message="message",
            )

    @pytest.mark.parametrize("message", [1, True, None, "", "   "])
    def test_message_must_be_nonblank_text(self, message: object) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=True,
                total_blocks=0,
                message=message,
            )

    def test_rejects_unknown_result_fields(self) -> None:
        with pytest.raises(ValidationError):
            VerificationResult(
                is_valid=True,
                total_blocks=0,
                message="message",
                unexpected="value",
            )

    def test_result_json_round_trip(self) -> None:
        result = VerificationResult(
            is_valid=False,
            total_blocks=4,
            violation_index=3,
            message="Signature mismatch",
        )

        restored = VerificationResult.model_validate_json(result.model_dump_json())

        assert restored == result

    def test_result_fields_are_immutable(self) -> None:
        result = VerificationResult(
            is_valid=True,
            total_blocks=0,
            message="message",
        )

        with pytest.raises(ValidationError):
            result.is_valid = False  # type: ignore[misc]