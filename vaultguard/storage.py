"""SQLite persistence and whole-ledger integrity verification.

The public storage API is append-only. SQLite triggers reject ordinary UPDATE
and DELETE operations, enforce sequential block indices, and advance a singleton
ledger-state anchor in the same transaction as every insertion.

The HMAC signing key is never persisted. A key must therefore be supplied each
time a ledger is opened.
"""

from __future__ import annotations

import math
import re
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from os import fspath as os_fspath
from os import fsdecode as os_fsdecode
from pathlib import Path
from typing import Final, Protocol, TypeAlias, runtime_checkable

from .engine import (
    SecretKey,
    canonical_json,
    compute_block_hash,
    generate_signature,
    hash_payload,
    verify_hmac_signature,
)
from .models import ZERO_HASH, AuditPayload, ChainBlock, VerificationResult


DatabasePath: TypeAlias = str | Path
PayloadSource: TypeAlias = AuditPayload | Mapping[str, object]

DEFAULT_DATABASE_PATH: Final[str] = "vaultguard.db"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 5.0
SCHEMA_VERSION: Final[int] = 1

BLOCKS_TABLE: Final[str] = "blocks"
LEDGER_STATE_TABLE: Final[str] = "ledger_state"

BLOCKS_NO_UPDATE_TRIGGER: Final[str] = "blocks_no_update"
BLOCKS_NO_DELETE_TRIGGER: Final[str] = "blocks_no_delete"
BLOCKS_SEQUENCE_TRIGGER: Final[str] = "blocks_sequence_guard"

LEDGER_STATE_ADVANCE_TRIGGER: Final[str] = "ledger_state_advance"
LEDGER_STATE_NO_UPDATE_TRIGGER: Final[str] = "ledger_state_no_update"
LEDGER_STATE_NO_DELETE_TRIGGER: Final[str] = "ledger_state_no_delete"
LEDGER_STATE_NO_INSERT_TRIGGER: Final[str] = "ledger_state_no_insert"

_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

_EXPECTED_COLUMNS: Final[dict[str, frozenset[str]]] = {
    BLOCKS_TABLE: frozenset(
        {
            "block_index",
            "payload_json",
            "payload_hash",
            "prev_hash",
            "current_hash",
            "signature",
        }
    ),
    LEDGER_STATE_TABLE: frozenset(
        {
            "singleton",
            "schema_version",
            "last_index",
            "last_hash",
        }
    ),
}

__all__ = [
    "AppendOnlyError",
    "BLOCKS_NO_DELETE_TRIGGER",
    "BLOCKS_NO_UPDATE_TRIGGER",
    "BLOCKS_SEQUENCE_TRIGGER",
    "BLOCKS_TABLE",
    "BlockValidationError",
    "CorruptLedgerError",
    "DEFAULT_DATABASE_PATH",
    "DEFAULT_TIMEOUT_SECONDS",
    "DatabasePath",
    "LEDGER_STATE_ADVANCE_TRIGGER",
    "LEDGER_STATE_NO_DELETE_TRIGGER",
    "LEDGER_STATE_NO_INSERT_TRIGGER",
    "LEDGER_STATE_NO_UPDATE_TRIGGER",
    "LEDGER_STATE_TABLE",
    "LedgerStorage",
    "SCHEMA_VERSION",
    "SQLiteAuditLedger",
    "SQLiteLedger",
    "SQLiteStorage",
    "StorageError",
    "StorageOperationError",
    "VaultGuardStorage",
    "verify_chain_integrity",
    "verify_ledger_integrity",
]


class StorageError(RuntimeError):
    """Base exception for persistent ledger failures."""


class StorageOperationError(StorageError):
    """A ledger operation could not be completed."""


class AppendOnlyError(StorageOperationError):
    """An operation attempted to mutate or bypass the append-only policy."""


class CorruptLedgerError(StorageError):
    """The persisted ledger is structurally or cryptographically corrupt."""

    def __init__(
        self,
        message: str,
        *,
        verification_result: VerificationResult | None = None,
    ) -> None:
        super().__init__(message)
        self.verification_result = verification_result
        self.result = verification_result


class BlockValidationError(CorruptLedgerError):
    """A persisted block cannot be decoded or fails intrinsic validation."""

    def __init__(self, block_index: int, message: str) -> None:
        self.block_index = block_index
        self.violation_index = block_index
        super().__init__(f"block {block_index}: {message}")


@runtime_checkable
class LedgerStorage(Protocol):
    """Structural interface implemented by persistent ledger backends."""

    def append(
        self,
        payload: PayloadSource,
        index: int | None = None,
    ) -> ChainBlock:
        """Append and return one signed block."""

    def get_block(self, index: int) -> ChainBlock:
        """Return one persisted block."""

    def verify_chain_integrity(self) -> VerificationResult:
        """Verify payload hashes, chain continuity, signatures, and state."""

    def close(self) -> None:
        """Close the underlying database connection."""


def _resolve_database_argument(
    path: DatabasePath | None,
    database: DatabasePath | None,
    database_path: DatabasePath | None,
) -> DatabasePath:
    supplied = [
        candidate
        for candidate in (path, database, database_path)
        if candidate is not None
    ]
    if len(supplied) != 1:
        names = "path, database, and database_path"
        raise TypeError(f"provide exactly one of {names}")

    try:
        value = os_fspath(supplied[0])
    except TypeError as exc:
        raise TypeError("database path must be a string or path-like object") from exc

    if isinstance(value, bytes):
        value = os_fsdecode(value)
    if not isinstance(value, str):
        raise TypeError("database path must resolve to a string")
    if not value:
        raise ValueError("database path must not be empty")

    return value


def _resolve_secret_key(
    secret_key: SecretKey | None,
    key: SecretKey | None,
    signing_key: SecretKey | None,
) -> bytes:
    supplied = [
        candidate
        for candidate in (secret_key, key, signing_key)
        if candidate is not None
    ]
    if len(supplied) != 1:
        raise TypeError(
            "provide exactly one of secret_key, key, or signing_key"
        )

    candidate = supplied[0]
    if isinstance(candidate, str):
        result = candidate.encode("utf-8")
    elif isinstance(candidate, (bytes, bytearray, memoryview)):
        result = bytes(candidate)
    else:
        raise TypeError("secret key must be str or bytes-like")

    if not result:
        raise ValueError("secret key must not be empty")

    return result


def _validate_timeout(timeout: float) -> float:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError("timeout must be a number")
    normalized = float(timeout)
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError("timeout must be a positive finite number")
    return normalized


def _is_uri(database_path: DatabasePath) -> bool:
    return isinstance(database_path, str) and database_path.startswith("file:")


def _connect(database_path: DatabasePath, timeout: float) -> sqlite3.Connection:
    connection = sqlite3.connect(
        os_fspath(database_path),
        timeout=timeout,
        isolation_level=None,
        check_same_thread=False,
        uri=_is_uri(database_path),
    )
    connection.row_factory = sqlite3.Row

    busy_timeout_ms = min(max(1, int(timeout * 1000)), 2_147_483_647)
    connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")

    foreign_keys = connection.execute("PRAGMA foreign_keys = ON").fetchone()[0]
    if foreign_keys != 1:
        connection.close()
        raise StorageOperationError("could not enable SQLite foreign keys")

    return connection


def _validate_table_columns(
    connection: sqlite3.Connection,
    table_name: str,
) -> None:
    escaped_table = table_name.replace('"', '""')
    rows = connection.execute(
        f'PRAGMA table_info("{escaped_table}")'
    ).fetchall()
    actual = frozenset(str(row["name"]) for row in rows)
    expected = _EXPECTED_COLUMNS[table_name]

    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing columns: {', '.join(missing)}")
        if extra:
            details.append(f"unexpected columns: {', '.join(extra)}")
        suffix = f" ({'; '.join(details)})" if details else ""
        raise CorruptLedgerError(
            f"table {table_name!r} has an invalid schema{suffix}"
        )


def _create_storage_policy(connection: sqlite3.Connection) -> None:
    statements = (
        f"""
        CREATE TRIGGER IF NOT EXISTS {BLOCKS_NO_UPDATE_TRIGGER}
        BEFORE UPDATE ON {BLOCKS_TABLE}
        BEGIN
            SELECT RAISE(ABORT, 'VaultGuard blocks are append-only');
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {BLOCKS_NO_DELETE_TRIGGER}
        BEFORE DELETE ON {BLOCKS_TABLE}
        BEGIN
            SELECT RAISE(ABORT, 'VaultGuard blocks are append-only');
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {BLOCKS_SEQUENCE_TRIGGER}
        BEFORE INSERT ON {BLOCKS_TABLE}
        BEGIN
            SELECT CASE
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM {LEDGER_STATE_TABLE}
                    WHERE singleton = 1
                )
                THEN RAISE(ABORT, 'VaultGuard ledger state is missing')

                WHEN NEW.block_index != (
                    SELECT last_index + 1
                    FROM {LEDGER_STATE_TABLE}
                    WHERE singleton = 1
                )
                THEN RAISE(ABORT, 'VaultGuard block index is not sequential')

                WHEN NEW.block_index = 0
                    AND NEW.prev_hash != '{ZERO_HASH}'
                THEN RAISE(ABORT, 'VaultGuard genesis prev_hash is invalid')

                WHEN NEW.block_index > 0
                    AND NEW.prev_hash != (
                        SELECT last_hash
                        FROM {LEDGER_STATE_TABLE}
                        WHERE singleton = 1
                    )
                THEN RAISE(ABORT, 'VaultGuard parent hash is invalid')

                ELSE NULL
            END;
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {LEDGER_STATE_ADVANCE_TRIGGER}
        AFTER INSERT ON {BLOCKS_TABLE}
        BEGIN
            UPDATE {LEDGER_STATE_TABLE}
            SET
                last_index = NEW.block_index,
                last_hash = NEW.current_hash
            WHERE singleton = 1;

            SELECT CASE
                WHEN changes() != 1
                THEN RAISE(ABORT, 'VaultGuard ledger state advance failed')
                ELSE NULL
            END;
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {LEDGER_STATE_NO_UPDATE_TRIGGER}
        BEFORE UPDATE ON {LEDGER_STATE_TABLE}
        WHEN NOT (
            OLD.singleton = 1
            AND NEW.singleton = 1
            AND OLD.schema_version = NEW.schema_version
            AND NEW.last_index = OLD.last_index + 1
        )
        BEGIN
            SELECT RAISE(ABORT, 'VaultGuard ledger state is append-only');
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {LEDGER_STATE_NO_DELETE_TRIGGER}
        BEFORE DELETE ON {LEDGER_STATE_TABLE}
        BEGIN
            SELECT RAISE(ABORT, 'VaultGuard ledger state is append-only');
        END
        """,
        f"""
        CREATE TRIGGER IF NOT EXISTS {LEDGER_STATE_NO_INSERT_TRIGGER}
        BEFORE INSERT ON {LEDGER_STATE_TABLE}
        WHEN NOT EXISTS (
            SELECT 1
            FROM {LEDGER_STATE_TABLE}
            WHERE singleton = 1
        )
        BEGIN
            SELECT RAISE(ABORT, 'VaultGuard ledger state already exists');
        END
        """,
    )

    for statement in statements:
        connection.execute(statement)


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {BLOCKS_TABLE} (
                block_index INTEGER PRIMARY KEY NOT NULL
                    CHECK (block_index >= 0),
                payload_json TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                signature TEXT NOT NULL
            )
            """
        )
        connection.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {LEDGER_STATE_TABLE} (
                singleton INTEGER PRIMARY KEY NOT NULL
                    CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                last_index INTEGER NOT NULL,
                last_hash TEXT NOT NULL
            )
            """
        )

        _validate_table_columns(connection, BLOCKS_TABLE)
        _validate_table_columns(connection, LEDGER_STATE_TABLE)

        state_count_row = connection.execute(
            f"SELECT COUNT(*) FROM {LEDGER_STATE_TABLE}"
        ).fetchone()
        if state_count_row is None:
            raise CorruptLedgerError("could not inspect VaultGuard ledger state")

        state_count = int(state_count_row[0])
        if state_count == 0:
            connection.execute(
                f"""
                INSERT INTO {LEDGER_STATE_TABLE} (
                    singleton,
                    schema_version,
                    last_index,
                    last_hash
                )
                VALUES (1, ?, -1, ?)
                """,
                (SCHEMA_VERSION, ZERO_HASH),
            )
        elif state_count != 1:
            raise CorruptLedgerError(
                "VaultGuard ledger state must contain exactly one singleton row"
            )

        _create_storage_policy(connection)
        connection.commit()
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise


class SQLiteLedger:
    """Persistent append-only SQLite implementation of :class:`LedgerStorage`."""

    def __init__(
        self,
        path: DatabasePath | None = None,
        secret_key: SecretKey | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        *,
        database: DatabasePath | None = None,
        database_path: DatabasePath | None = None,
        key: SecretKey | None = None,
        signing_key: SecretKey | None = None,
    ) -> None:
        self._database_path = _resolve_database_argument(
            path,
            database,
            database_path,
        )
        self._secret_key = _resolve_secret_key(
            secret_key,
            key,
            signing_key,
        )
        self._timeout = _validate_timeout(timeout)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None

        try:
            self._connection = _connect(
                self._database_path,
                self._timeout,
            )
            _initialize_schema(self._connection)
        except CorruptLedgerError:
            self._discard_connection()
            raise
        except sqlite3.Error as exc:
            self._discard_connection()
            raise StorageOperationError(
                f"could not initialize VaultGuard database: {exc}"
            ) from exc
        except Exception:
            self._discard_connection()
            raise

    @property
    def database_path(self) -> DatabasePath:
        """Return the path or SQLite URI used to open this ledger."""

        return self._database_path

    def __enter__(self) -> SQLiteLedger:
        self._require_connection()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __iter__(self) -> Iterator[ChainBlock]:
        return self.iter_blocks()

    def __len__(self) -> int:
        return self.count_blocks()

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StorageOperationError("ledger is closed")
        return self._connection

    def _discard_connection(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()

    @staticmethod
    def _coerce_block_index(index: object) -> int:
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise ValueError("block index must be a non-negative integer")
        return index

    @staticmethod
    def _coerce_payload(payload: PayloadSource) -> AuditPayload:
        if isinstance(payload, AuditPayload):
            return payload
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be an AuditPayload or JSON object")
        return AuditPayload.model_validate(dict(payload))

    @staticmethod
    def _result(
        *,
        is_valid: bool,
        blocks_verified: int,
        violation_index: int | None,
        message: str,
    ) -> VerificationResult:
        return VerificationResult(
            is_valid=is_valid,
            blocks_verified=blocks_verified,
            violation_index=violation_index,
            message=message,
        )

    def _block_from_row(self, row: sqlite3.Row) -> ChainBlock:
        raw_index = row["block_index"]
        if not isinstance(raw_index, int) or isinstance(raw_index, bool) or raw_index < 0:
            raise BlockValidationError(
                0 if not isinstance(raw_index, int) else raw_index,
                "block index must be a non-negative integer",
            )

        payload_json = row["payload_json"]
        if not isinstance(payload_json, str):
            raise BlockValidationError(
                raw_index,
                "payload_json must contain UTF-8 JSON text",
            )

        try:
            payload = AuditPayload.model_validate_json(payload_json)
        except Exception as exc:
            raise BlockValidationError(
                raw_index,
                f"payload JSON is invalid: {exc}",
            ) from exc

        try:
            canonical_payload = canonical_json(payload)
        except Exception as exc:
            raise BlockValidationError(
                raw_index,
                f"payload cannot be canonicalized: {exc}",
            ) from exc

        if payload_json != canonical_payload:
            raise BlockValidationError(
                raw_index,
                "payload JSON is not in canonical form",
            )

        payload_hash = row["payload_hash"]
        prev_hash = row["prev_hash"]
        current_hash = row["current_hash"]
        signature = row["signature"]

        if not isinstance(payload_hash, str) or not _SHA256_HEX_RE.fullmatch(
            payload_hash
        ):
            raise BlockValidationError(
                raw_index,
                "payload_hash must be 64 lowercase hexadecimal characters",
            )
        if not isinstance(prev_hash, str) or not _SHA256_HEX_RE.fullmatch(prev_hash):
            raise BlockValidationError(
                raw_index,
                "prev_hash must be 64 lowercase hexadecimal characters",
            )
        if not isinstance(current_hash, str) or not _SHA256_HEX_RE.fullmatch(
            current_hash
        ):
            raise BlockValidationError(
                raw_index,
                "current_hash must be 64 lowercase hexadecimal characters",
            )
        if not isinstance(signature, str) or not _SHA256_HEX_RE.fullmatch(signature):
            raise BlockValidationError(
                raw_index,
                "signature must be 64 lowercase hexadecimal characters",
            )

        calculated_payload_hash = hash_payload(payload)
        if not hmac_compare(payload_hash, calculated_payload_hash):
            raise BlockValidationError(
                raw_index,
                "payload hash mismatch",
            )

        calculated_current_hash = compute_block_hash(
            raw_index,
            calculated_payload_hash,
            prev_hash,
        )
        if not hmac_compare(current_hash, calculated_current_hash):
            raise BlockValidationError(
                raw_index,
                "block hash mismatch",
            )

        try:
            return ChainBlock(
                index=raw_index,
                payload=payload,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
                current_hash=current_hash,
                signature=signature,
            )
        except Exception as exc:
            raise BlockValidationError(
                raw_index,
                f"block schema is invalid: {exc}",
            ) from exc

    def _verify_connection(
        self,
        connection: sqlite3.Connection,
    ) -> VerificationResult:
        blocks_verified = 0
        expected_index = 0
        previous_hash = ZERO_HASH

        try:
            rows = connection.execute(
                f"""
                SELECT
                    block_index,
                    payload_json,
                    payload_hash,
                    prev_hash,
                    current_hash,
                    signature
                FROM {BLOCKS_TABLE}
                ORDER BY block_index ASC
                """
            )
            for row in rows:
                actual_index = row["block_index"]
                if not isinstance(actual_index, int) or isinstance(actual_index, bool):
                    return self._result(
                        is_valid=False,
                        blocks_verified=blocks_verified,
                        violation_index=expected_index,
                        message="persisted block index is not an integer",
                    )

                if actual_index != expected_index:
                    return self._result(
                        is_valid=False,
                        blocks_verified=blocks_verified,
                        violation_index=expected_index,
                        message=(
                            f"missing or out-of-sequence block index; "
                            f"expected {expected_index}, found {actual_index}"
                        ),
                    )

                try:
                    block = self._block_from_row(row)
                except BlockValidationError as exc:
                    return self._result(
                        is_valid=False,
                        blocks_verified=blocks_verified,
                        violation_index=expected_index,
                        message=exc.message,
                    )

                if not hmac_compare(block.prev_hash, previous_hash):
                    return self._result(
                        is_valid=False,
                        blocks_verified=blocks_verified,
                        violation_index=expected_index,
                        message=(
                            f"parent hash mismatch at block {expected_index}; "
                            f"expected {previous_hash}"
                        ),
                    )

                if not verify_hmac_signature(
                    block.current_hash,
                    block.signature,
                    self._secret_key,
                ):
                    return self._result(
                        is_valid=False,
                        blocks_verified=blocks_verified,
                        violation_index=expected_index,
                        message=(
                            f"HMAC signature verification failed at block "
                            f"{expected_index}"
                        ),
                    )

                blocks_verified += 1
                previous_hash = block.current_hash
                expected_index += 1
        except sqlite3.Error as exc:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message=f"could not traverse ledger: {exc}",
            )

        try:
            state_rows = connection.execute(
                f"""
                SELECT singleton, schema_version, last_index, last_hash
                FROM {LEDGER_STATE_TABLE}
                """
            ).fetchall()
        except sqlite3.Error as exc:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message=f"could not read ledger state: {exc}",
            )

        if len(state_rows) != 1:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message="ledger state must contain exactly one singleton row",
            )

        state = state_rows[0]
        if state["singleton"] != 1:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message="ledger state singleton is invalid",
            )
        if state["schema_version"] != SCHEMA_VERSION:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message=(
                    f"unsupported ledger schema version "
                    f"{state['schema_version']!r}"
                ),
            )

        state_last_index = state["last_index"]
        if (
            not isinstance(state_last_index, int)
            or isinstance(state_last_index, bool)
        ):
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message="ledger state last_index is not an integer",
            )

        expected_last_index = expected_index - 1
        if state_last_index != expected_last_index:
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message=(
                    f"ledger state reports last index {state_last_index}, but "
                    f"the verified chain ends at {expected_last_index}; "
                    f"blocks may have been inserted or deleted"
                ),
            )

        state_last_hash = state["last_hash"]
        if not isinstance(state_last_hash, str) or not hmac_compare(
            state_last_hash,
            previous_hash,
        ):
            return self._result(
                is_valid=False,
                blocks_verified=blocks_verified,
                violation_index=expected_index,
                message="ledger state last_hash does not match the verified chain",
            )

        return self._result(
            is_valid=True,
            blocks_verified=blocks_verified,
            violation_index=None,
            message=(
                "chain integrity verified"
                if blocks_verified
                else "empty ledger chain integrity verified"
            ),
        )

    def append(
        self,
        payload: PayloadSource,
        index: int | None = None,
    ) -> ChainBlock:
        """Atomically validate, create, sign, and append one audit block."""

        normalized_payload = self._coerce_payload(payload)
        explicit_index: int | None = None
        if index is not None:
            explicit_index = self._coerce_block_index(index)

        with self._lock:
            connection = self._require_connection()
            try:
                connection.execute("BEGIN IMMEDIATE")

                verification = self._verify_connection(connection)
                if not verification.is_valid:
                    raise CorruptLedgerError(
                        (
                            "refusing to append to a corrupt ledger: "
                            f"{verification.message}"
                        ),
                        verification_result=verification,
                    )

                state_row = connection.execute(
                    f"""
                    SELECT last_index, last_hash
                    FROM {LEDGER_STATE_TABLE}
                    WHERE singleton = 1
                    """
                ).fetchone()
                if state_row is None:
                    raise CorruptLedgerError(
                        "refusing to append: ledger state is missing"
                    )

                last_index = state_row["last_index"]
                previous_hash = state_row["last_hash"]
                next_index = last_index + 1

                if explicit_index is not None and explicit_index != next_index:
                    raise AppendOnlyError(
                        (
                            f"explicit block index {explicit_index} does not match "
                            f"the next sequential index {next_index}"
                        )
                    )

                payload_hash = hash_payload(normalized_payload)
                current_hash = compute_block_hash(
                    next_index,
                    payload_hash,
                    previous_hash,
                )
                signature = generate_signature(current_hash, self._secret_key)

                block = ChainBlock(
                    index=next_index,
                    payload=normalized_payload,
                    payload_hash=payload_hash,
                    prev_hash=previous_hash,
                    current_hash=current_hash,
                    signature=signature,
                )

                connection.execute(
                    f"""
                    INSERT INTO {BLOCKS_TABLE} (
                        block_index,
                        payload_json,
                        payload_hash,
                        prev_hash,
                        current_hash,
                        signature
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        block.index,
                        canonical_json(block.payload),
                        block.payload_hash,
                        block.prev_hash,
                        block.current_hash,
                        block.signature,
                    ),
                )
                connection.commit()
                return block
            except sqlite3.IntegrityError as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise AppendOnlyError(
                    f"append rejected by the VaultGuard storage policy: {exc}"
                ) from exc
            except sqlite3.Error as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise StorageOperationError(
                    f"could not append audit block: {exc}"
                ) from exc
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise

    append_block = append
    append_event = append
    append_payload = append

    def get_block(self, index: int) -> ChainBlock:
        """Return and intrinsically validate one persisted block."""

        normalized_index = self._coerce_block_index(index)
        with self._lock:
            connection = self._require_connection()
            try:
                row = connection.execute(
                    f"""
                    SELECT
                        block_index,
                        payload_json,
                        payload_hash,
                        prev_hash,
                        current_hash,
                        signature
                    FROM {BLOCKS_TABLE}
                    WHERE block_index = ?
                    """,
                    (normalized_index,),
                ).fetchone()
            except sqlite3.Error as exc:
                raise StorageOperationError(
                    f"could not read block {normalized_index}: {exc}"
                ) from exc

        if row is None:
            raise IndexError(f"block index {normalized_index} does not exist")

        return self._block_from_row(row)

    read_block = get_block

    def iter_blocks(
        self,
        start: int = 0,
        end: int | None = None,
    ) -> Iterator[ChainBlock]:
        """Yield persisted blocks in ascending index order."""

        normalized_start = self._coerce_block_index(start)
        normalized_end: int | None = None
        if end is not None:
            normalized_end = self._coerce_block_index(end)
            if normalized_end < normalized_start:
                raise ValueError("end must not be less than start")

        current_index = normalized_start
        while normalized_end is None or current_index <= normalized_end:
            with self._lock:
                connection = self._require_connection()
                try:
                    row = connection.execute(
                        f"""
                        SELECT
                            block_index,
                            payload_json,
                            payload_hash,
                            prev_hash,
                            current_hash,
                            signature
                        FROM {BLOCKS_TABLE}
                        WHERE block_index = ?
                        """,
                        (current_index,),
                    ).fetchone()
                except sqlite3.Error as exc:
                    raise StorageOperationError(
                        f"could not traverse ledger at block {current_index}: {exc}"
                    ) from exc

            if row is None:
                return

            yield self._block_from_row(row)
            current_index += 1

    def count_blocks(self) -> int:
        """Return the number of physically persisted block rows."""

        with self._lock:
            connection = self._require_connection()
            try:
                row = connection.execute(
                    f"SELECT COUNT(*) FROM {BLOCKS_TABLE}"
                ).fetchone()
            except sqlite3.Error as exc:
                raise StorageOperationError(
                    f"could not count ledger blocks: {exc}"
                ) from exc

        if row is None:
            raise StorageOperationError("could not count ledger blocks")
        return int(row[0])

    def verify_chain_integrity(self) -> VerificationResult:
        """Verify the complete persisted chain and ledger-state anchor."""

        with self._lock:
            connection = self._require_connection()
            return self._verify_connection(connection)

    def close(self) -> None:
        """Close the ledger. Calling ``close`` more than once is harmless."""

        with self._lock:
            self._discard_connection()


def hmac_compare(first: str, second: str) -> bool:
    """Compare two already-validated hexadecimal strings safely."""

    # Length is fixed for all cryptographic comparisons. Importing compare_digest
    # locally keeps the public cryptographic implementation in the engine module.
    import hmac

    return hmac.compare_digest(first, second)


def verify_chain_integrity(
    database: DatabasePath | None = None,
    secret_key: SecretKey | None = None,
    *,
    path: DatabasePath | None = None,
    database_path: DatabasePath | None = None,
    key: SecretKey | None = None,
    signing_key: SecretKey | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> VerificationResult:
    """Open a ledger temporarily and return its integrity verification result."""

    with SQLiteLedger(
        path=path,
        secret_key=secret_key,
        timeout=timeout,
        database=database,
        database_path=database_path,
        key=key,
        signing_key=signing_key,
    ) as ledger:
        return ledger.verify_chain_integrity()


def verify_ledger_integrity(
    database: DatabasePath | None = None,
    secret_key: SecretKey | None = None,
    *,
    path: DatabasePath | None = None,
    database_path: DatabasePath | None = None,
    key: SecretKey | None = None,
    signing_key: SecretKey | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> VerificationResult:
    """Compatibility alias for :func:`verify_chain_integrity`."""

    return verify_chain_integrity(
        database,
        secret_key,
        path=path,
        database_path=database_path,
        key=key,
        signing_key=signing_key,
        timeout=timeout,
    )


SQLiteAuditLedger = SQLiteLedger
SQLiteStorage = SQLiteLedger
VaultGuardStorage = SQLiteLedger