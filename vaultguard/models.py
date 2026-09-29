"""Strict, immutable domain models for the VaultGuard audit ledger."""

from __future__ import annotations

import math
import unicodedata
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

ZERO_HASH: Final[str] = "0" * 64

ActorId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=256, pattern=r"\S"),
]

Sha256Hex = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    ),
]

NonNegativeInteger = Annotated[int, Field(strict=True, ge=0)]
JsonObject = dict[str, JsonValue]

VerificationMessage = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=4096,
        pattern=r"\S",
    ),
]


class AuditAction(str, Enum):
    """Controlled vocabulary of supported security audit actions."""

    LOGIN = "login"
    LOGOUT = "logout"
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    ADMIN_OVERRIDE = "admin_override"
    CREDENTIAL_ROTATION = "credential_rotation"
    DATABASE_MIGRATION = "database_migration"


class _StrictDomainModel(BaseModel):
    """Configuration shared by every persisted VaultGuard domain model."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        allow_inf_nan=False,
    )


def _as_utc_datetime(value: object) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC.

    Python callers may provide either an aware ``datetime`` or an ISO-8601
    string. Naive timestamps and timestamps with a non-zero UTC offset are
    rejected rather than being silently altered.
    """

    if isinstance(value, str):
        candidate = f"{value[:-1]}+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("timestamp must be a valid ISO-8601 datetime") from exc
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise ValueError("timestamp must be an ISO-8601 string or datetime")

    if parsed.tzinfo is None:
        raise ValueError("timestamp must include an explicit UTC offset")

    try:
        offset = parsed.utcoffset()
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError("timestamp contains an invalid UTC offset") from exc

    if offset is None:
        raise ValueError("timestamp must include an explicit UTC offset")
    if offset != timedelta(0):
        raise ValueError("timestamp must use UTC (Z or an offset of +00:00)")

    try:
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise ValueError("timestamp cannot be normalized to UTC") from exc


def _validate_identifier(value: str, *, field_name: str) -> str:
    """Reject blank, padded, or visually ambiguous control characters."""

    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if value != value.strip():
        raise ValueError(
            f"{field_name} must not have leading or trailing whitespace"
        )

    # Reject Unicode control and private-use characters, plus line and
    # paragraph separators that could create misleading log output.
    forbidden_categories = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
    if any(unicodedata.category(character) in forbidden_categories for character in value):
        raise ValueError(f"{field_name} must not contain control characters")

    return value


def _validate_strict_json_value(
    value: object,
    *,
    active_containers: set[int] | None = None,
) -> None:
    """Reject non-JSON values, non-finite floats, and recursive containers."""

    if active_containers is None:
        active_containers = set()

    if isinstance(value, dict):
        container_id = id(value)
        if container_id in active_containers:
            raise ValueError("metadata must not contain recursive objects")

        active_containers.add(container_id)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("metadata object keys must be strings")
                _validate_strict_json_value(
                    item,
                    active_containers=active_containers,
                )
        finally:
            active_containers.remove(container_id)
        return

    if isinstance(value, list):
        container_id = id(value)
        if container_id in active_containers:
            raise ValueError("metadata must not contain recursive arrays")

        active_containers.add(container_id)
        try:
            for item in value:
                _validate_strict_json_value(
                    item,
                    active_containers=active_containers,
                )
        finally:
            active_containers.remove(container_id)
        return

    if value is None or isinstance(value, (str, bool, int)):
        return

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("metadata must not contain NaN or infinite numbers")
        return

    raise ValueError(
        "metadata must contain only JSON-compatible strings, numbers, "
        "booleans, null, objects, and arrays"
    )


class AuditPayload(_StrictDomainModel):
    """Security event data whose canonical bytes are hashed into the chain."""

    timestamp: datetime
    actor: ActorId
    action: AuditAction
    metadata: JsonObject = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, value: object) -> datetime:
        return _as_utc_datetime(value)

    @field_validator("actor")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return _validate_identifier(value, field_name="actor")

    @field_validator("action", mode="before")
    @classmethod
    def parse_action(cls, value: object) -> AuditAction:
        if isinstance(value, AuditAction):
            return value
        if isinstance(value, str):
            try:
                return AuditAction(value)
            except ValueError as exc:
                raise ValueError("action is not a supported audit action") from exc
        raise ValueError("action must be a string or AuditAction")

    @field_validator("metadata", mode="before")
    @classmethod
    def validate_metadata(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("metadata must be a JSON object")
        _validate_strict_json_value(value)
        return value


class ChainBlock(_StrictDomainModel):
    """A payload and its cryptographic position in the immutable chain."""

    index: NonNegativeInteger
    payload: AuditPayload
    payload_hash: Sha256Hex
    prev_hash: Sha256Hex
    current_hash: Sha256Hex
    signature: Sha256Hex

    @field_validator("payload", mode="before")
    @classmethod
    def require_payload_instance_in_python_mode(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        """Require a model instance for Python API calls.

        JSON has no representation for a Python model instance, so a JSON
        object is validated as an ``AuditPayload`` in JSON mode. This retains
        strict instance-only behavior for ordinary Python construction while
        supporting standards-compliant serialization round trips.
        """

        if isinstance(value, AuditPayload):
            return value

        if info.mode == "json" and isinstance(value, dict):
            return AuditPayload.model_validate(value)

        raise ValueError(
            "payload must be an AuditPayload instance in Python mode"
        )

    @model_validator(mode="after")
    def validate_chain_position(self) -> ChainBlock:
        if self.index == 0 and self.prev_hash != ZERO_HASH:
            raise ValueError("the genesis block must have a zero prev_hash")
        if self.index > 0 and self.prev_hash == ZERO_HASH:
            raise ValueError("non-genesis blocks must not have a zero prev_hash")
        return self


class VerificationResult(_StrictDomainModel):
    """Outcome of a whole-chain integrity verification operation."""

    is_valid: Annotated[bool, Field(strict=True)]
    total_blocks: NonNegativeInteger
    violation_index: NonNegativeInteger | None = None
    message: VerificationMessage

    @model_validator(mode="after")
    def validate_result_consistency(self) -> VerificationResult:
        if self.is_valid and self.violation_index is not None:
            raise ValueError(
                "a valid verification result must not contain a violation_index"
            )

        if not self.is_valid and self.violation_index is None:
            raise ValueError(
                "an invalid verification result must identify a violation_index"
            )

        if (
            self.violation_index is not None
            and self.violation_index >= self.total_blocks
        ):
            raise ValueError("violation_index must be less than total_blocks")

        return self


__all__ = [
    "ZERO_HASH",
    "AuditAction",
    "AuditPayload",
    "ChainBlock",
    "VerificationResult",
]