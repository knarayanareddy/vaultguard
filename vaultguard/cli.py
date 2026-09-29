"""Command-line interface for the VaultGuard append-only audit ledger."""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import sys
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

from pydantic import ValidationError

from .engine import canonical_json
from .models import AuditAction, AuditPayload, VerificationResult
from .storage import (
    BLOCKS_NO_UPDATE_TRIGGER,
    BLOCKS_TABLE,
    DEFAULT_DATABASE_PATH,
    DEFAULT_TIMEOUT_SECONDS,
    SQLiteLedger,
    StorageError,
)


EXIT_SUCCESS: Final[int] = 0
EXIT_INTEGRITY_FAILURE: Final[int] = 1
EXIT_USAGE_ERROR: Final[int] = 2

DEFAULT_SECRET_KEY_ENV: Final[str] = "VAULTGUARD_SECRET_KEY"
_MAX_METADATA_BYTES: Final[int] = 1024 * 1024
_MAX_KEY_FILE_BYTES: Final[int] = 64 * 1024
_MAX_DEMO_INDEX: Final[int] = 10_000

__all__ = [
    "CLIError",
    "EXIT_INTEGRITY_FAILURE",
    "EXIT_SUCCESS",
    "EXIT_USAGE_ERROR",
    "build_parser",
    "main",
]


class CLIError(ValueError):
    """A user-facing command-line error."""


def _non_negative_index(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("index must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("index must be non-negative")
    return parsed


def _demo_index(value: str) -> int:
    parsed = _non_negative_index(value)
    if parsed > _MAX_DEMO_INDEX:
        raise argparse.ArgumentTypeError(
            f"demo index must not exceed {_MAX_DEMO_INDEX}"
        )
    return parsed


def _non_negative_count(value: str) -> int:
    parsed = _non_negative_index(value)
    if parsed > _MAX_DEMO_INDEX + 1:
        raise argparse.ArgumentTypeError(
            f"demo count must not exceed {_MAX_DEMO_INDEX + 1}"
        )
    return parsed


def _positive_timeout(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("timeout must be a positive finite number")
    return parsed


def _add_storage_arguments(
    parser: argparse.ArgumentParser,
    *,
    subcommand: bool,
) -> None:
    default: object = argparse.SUPPRESS if subcommand else None

    parser.add_argument(
        "--db",
        "--database",
        "--database-path",
        dest="database_path",
        metavar="PATH",
        default=default,
        help=(
            "SQLite database path or URI "
            f"(default: {DEFAULT_DATABASE_PATH}, VAULTGUARD_DB, or "
            "VAULTGUARD_DATABASE)"
        ),
    )
    parser.add_argument(
        "--key",
        "--secret-key",
        dest="secret_key",
        metavar="KEY",
        default=default,
        help=(
            "HMAC key; prefer --secret-key-env or an environment variable "
            "to avoid exposing the key in the process list"
        ),
    )
    parser.add_argument(
        "--secret-key-env",
        dest="secret_key_env",
        metavar="ENV_NAME",
        default=default,
        help=(
            "read the HMAC key from this environment variable "
            f"(default: {DEFAULT_SECRET_KEY_ENV})"
        ),
    )
    parser.add_argument(
        "--key-file",
        dest="key_file",
        metavar="PATH",
        default=default,
        help="read the HMAC key from a file",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        metavar="SECONDS",
        type=_positive_timeout,
        default=default,
        help=f"SQLite busy timeout (default: {DEFAULT_TIMEOUT_SECONDS})",
    )


def _add_output_arguments(
    parser: argparse.ArgumentParser,
    *,
    default_format: str,
) -> None:
    parser.add_argument(
        "--format",
        "--output",
        dest="output_format",
        choices=("text", "json"),
        default=default_format,
        help=f"output format (default: {default_format})",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="shorthand for JSON output",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the complete VaultGuard command-line parser."""

    parser = argparse.ArgumentParser(
        prog="vaultguard",
        description=(
            "Append cryptographically signed events and verify the complete "
            "VaultGuard hash chain."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="vaultguard 0.1.0",
    )
    _add_storage_arguments(parser, subcommand=False)

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="COMMAND",
    )

    append_parser = subparsers.add_parser(
        "append",
        help="append one structured audit event",
        description="Append one structured audit event to the ledger.",
    )
    _add_storage_arguments(append_parser, subcommand=True)
    append_parser.add_argument(
        "--actor",
        required=True,
        help="authenticated actor identifier",
    )
    append_parser.add_argument(
        "--action",
        required=True,
        choices=tuple(action.value for action in AuditAction),
        help="controlled audit action",
    )
    append_parser.add_argument(
        "--timestamp",
        metavar="UTC_ISO8601",
        help="explicit UTC timestamp (default: current UTC time)",
    )
    metadata_group = append_parser.add_mutually_exclusive_group()
    metadata_group.add_argument(
        "--metadata",
        metavar="JSON",
        help="metadata JSON object",
    )
    metadata_group.add_argument(
        "--metadata-file",
        metavar="PATH",
        help="file containing a metadata JSON object",
    )
    append_parser.add_argument(
        "--index",
        type=_non_negative_index,
        help="explicit expected next index",
    )
    _add_output_arguments(append_parser, default_format="json")

    verify_parser = subparsers.add_parser(
        "verify",
        help="verify the complete chain",
        description="Verify every payload hash, chain link, signature, and state anchor.",
    )
    _add_storage_arguments(verify_parser, subcommand=True)
    _add_output_arguments(verify_parser, default_format="text")

    tamper_parser = subparsers.add_parser(
        "tamper-demo",
        help="modify one payload and demonstrate detection",
        description=(
            "Drop the update guard, alter one persisted payload, and verify that "
            "the tampering is detected."
        ),
    )
    _add_storage_arguments(tamper_parser, subcommand=True)
    tamper_parser.add_argument(
        "--index",
        type=_demo_index,
        default=0,
        help="block index to alter (default: 0)",
    )
    tamper_parser.add_argument(
        "--field",
        choices=("actor", "timestamp", "metadata"),
        default="actor",
        help="payload field to alter (default: actor)",
    )
    tamper_parser.add_argument(
        "--ephemeral",
        "--temporary",
        dest="ephemeral",
        action="store_true",
        help="create and tamper a temporary ledger instead of modifying --db",
    )
    tamper_parser.add_argument(
        "--in-place",
        dest="ephemeral",
        action="store_false",
        help="explicitly modify the selected ledger (default)",
    )
    tamper_parser.set_defaults(ephemeral=False)
    tamper_parser.add_argument(
        "--count",
        "--blocks",
        dest="count",
        type=_non_negative_count,
        help=(
            "number of blocks to create for an ephemeral demonstration "
            "(default: index + 1)"
        ),
    )
    tamper_parser.add_argument(
        "--actor",
        default="vaultguard-demo",
        help="actor prefix for an ephemeral demonstration",
    )
    tamper_parser.add_argument(
        "--action",
        choices=tuple(action.value for action in AuditAction),
        default=AuditAction.LOGIN.value,
        help="action for an ephemeral demonstration",
    )
    _add_output_arguments(tamper_parser, default_format="text")

    return parser


def _wants_json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json_output", False)) or (
        getattr(args, "output_format", "text") == "json"
    )


def _resolve_database(args: argparse.Namespace) -> str:
    value = getattr(args, "database_path", None)
    if value is None:
        value = os.environ.get("VAULTGUARD_DB")
    if value is None:
        value = os.environ.get("VAULTGUARD_DATABASE")
    if value is None:
        value = DEFAULT_DATABASE_PATH

    try:
        resolved = os.fspath(value)
    except TypeError as exc:
        raise CLIError("database path must be a string or path-like object") from exc

    if isinstance(resolved, bytes):
        resolved = os.fsdecode(resolved)
    if not isinstance(resolved, str):
        raise CLIError("database path must resolve to a string")
    if not resolved:
        raise CLIError("database path must not be empty")
    return resolved


def _read_key_file(path: str) -> str:
    try:
        file_path = Path(path)
        if file_path.stat().st_size > _MAX_KEY_FILE_BYTES:
            raise CLIError("key file is too large")
        data = file_path.read_bytes()
    except CLIError:
        raise
    except OSError as exc:
        raise CLIError(f"could not read key file: {exc}") from exc

    if len(data) > _MAX_KEY_FILE_BYTES:
        raise CLIError("key file is too large")

    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CLIError("key file must contain UTF-8 text") from exc

    value = value.rstrip("\r\n")
    if not value:
        raise CLIError("key file must not be empty")
    return value


def _resolve_secret_key(args: argparse.Namespace) -> str:
    explicit = getattr(args, "secret_key", None)
    key_file = getattr(args, "key_file", None)

    if explicit is not None and key_file is not None:
        raise CLIError("use either --key/--secret-key or --key-file, not both")

    if key_file is not None:
        return _read_key_file(str(key_file))

    if explicit is not None:
        if not isinstance(explicit, str) or not explicit:
            raise CLIError("HMAC key must not be empty")
        return explicit

    environment_name = getattr(args, "secret_key_env", None)
    if environment_name is None:
        environment_name = DEFAULT_SECRET_KEY_ENV

    if not isinstance(environment_name, str) or not environment_name:
        raise CLIError("secret-key environment variable name must not be empty")

    value = os.environ.get(environment_name)
    if value is None:
        value = os.environ.get("VAULTGUARD_HMAC_KEY")
    if value is None:
        value = os.environ.get("VAULTGUARD_KEY")
    if value is None:
        raise CLIError(
            f"no HMAC key supplied; use --secret-key-env or set {environment_name}"
        )
    if not value:
        raise CLIError("HMAC key must not be empty")
    return value


def _resolve_timeout(args: argparse.Namespace) -> float:
    value = getattr(args, "timeout", None)
    if value is None:
        value = DEFAULT_TIMEOUT_SECONDS
    return _validate_cli_timeout(value)


def _validate_cli_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CLIError("timeout must be a number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise CLIError("timeout must be a positive finite number")
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _decode_metadata(text: str) -> dict[str, object]:
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_METADATA_BYTES:
        raise CLIError(
            f"metadata exceeds the {_MAX_METADATA_BYTES}-byte limit"
        )

    try:
        value = json.loads(
            text,
            parse_constant=_reject_nonfinite_json,
            object_pairs_hook=_unique_json_object,
        )
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise CLIError(f"metadata is not valid JSON: {exc}") from exc

    if not isinstance(value, dict):
        raise CLIError("metadata must be a JSON object")
    return value


def _read_metadata(args: argparse.Namespace) -> dict[str, object]:
    inline = getattr(args, "metadata", None)
    metadata_file = getattr(args, "metadata_file", None)

    if inline is not None:
        return _decode_metadata(inline)

    if metadata_file is None:
        return {}

    try:
        path = Path(str(metadata_file))
        if path.stat().st_size > _MAX_METADATA_BYTES:
            raise CLIError(
                f"metadata file exceeds the {_MAX_METADATA_BYTES}-byte limit"
            )
        data = path.read_bytes()
    except CLIError:
        raise
    except OSError as exc:
        raise CLIError(f"could not read metadata file: {exc}") from exc

    if len(data) > _MAX_METADATA_BYTES:
        raise CLIError(
            f"metadata file exceeds the {_MAX_METADATA_BYTES}-byte limit"
        )

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CLIError("metadata file must contain UTF-8 text") from exc

    return _decode_metadata(text)


def _append_command(args: argparse.Namespace) -> int:
    database_path = _resolve_database(args)
    secret_key = _resolve_secret_key(args)
    timeout = _resolve_timeout(args)

    timestamp: datetime | str
    if args.timestamp is None:
        timestamp = datetime.now(timezone.utc)
    else:
        timestamp = args.timestamp

    try:
        payload = AuditPayload(
            timestamp=timestamp,
            actor=args.actor,
            action=args.action,
            metadata=_read_metadata(args),
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise CLIError(f"invalid audit event: {exc}") from exc

    with SQLiteLedger(
        database=database_path,
        secret_key=secret_key,
        timeout=timeout,
    ) as ledger:
        block = ledger.append(payload, index=args.index)
        result = block.model_dump(mode="json")

    if _wants_json(args):
        output = {"status": "appended", **result}
        print(canonical_json(output))
    else:
        print(
            f"Appended block {block.index}: "
            f"current_hash={block.current_hash}"
        )
    return EXIT_SUCCESS


def _print_verification_text(
    result: VerificationResult,
    blocks: Sequence[object],
) -> None:
    status = "VALID" if result.is_valid else "INVALID"
    print(f"Chain integrity: {status}")
    print(f"Blocks verified: {result.blocks_verified}")

    if result.violation_index is not None:
        print(f"Violation index: {result.violation_index}")
    print(f"Message: {result.message}")

    if not result.is_valid or not blocks:
        return

    print()
    print(f"{'INDEX':>8}  {'PAYLOAD HASH':<64}  {'PREVIOUS HASH':<64}  CURRENT HASH")
    print(f"{'-' * 8}  {'-' * 64}  {'-' * 64}  {'-' * 64}")
    for block in blocks:
        print(
            f"{block.index:>8}  "
            f"{block.payload_hash:<64}  "
            f"{block.prev_hash:<64}  "
            f"{block.current_hash}"
        )


def _verify_command(args: argparse.Namespace) -> int:
    database_path = _resolve_database(args)
    secret_key = _resolve_secret_key(args)
    timeout = _resolve_timeout(args)

    with SQLiteLedger(
        database=database_path,
        secret_key=secret_key,
        timeout=timeout,
    ) as ledger:
        result = ledger.verify_chain_integrity()
        blocks = list(ledger) if result.is_valid else []

    if _wants_json(args):
        print(canonical_json(result.model_dump(mode="json")))
    else:
        _print_verification_text(result, blocks)

    return EXIT_SUCCESS if result.is_valid else EXIT_INTEGRITY_FAILURE


def _is_sqlite_uri(path: str) -> bool:
    return path.startswith("file:")


def _tamper_database(
    database_path: str,
    block_index: int,
    field: str,
    timeout: float,
) -> None:
    try:
        connection = sqlite3.connect(
            database_path,
            timeout=timeout,
            uri=_is_sqlite_uri(database_path),
        )
    except sqlite3.Error as exc:
        raise CLIError(f"could not open database for tamper demo: {exc}") from exc

    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            f"""
            SELECT payload_json
            FROM {BLOCKS_TABLE}
            WHERE block_index = ?
            """,
            (block_index,),
        ).fetchone()
        if row is None:
            raise CLIError(f"block index {block_index} does not exist")

        try:
            payload = json.loads(row[0])
        except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
            raise CLIError(
                f"block {block_index} contains invalid payload JSON"
            ) from exc
        if not isinstance(payload, dict):
            raise CLIError(
                f"block {block_index} payload is not a JSON object"
            )

        if field == "actor":
            altered_actor = "vaultguard-tamper-demo"
            if payload.get("actor") == altered_actor:
                altered_actor = "vaultguard-tamper-demo-2"
            payload["actor"] = altered_actor
        elif field == "timestamp":
            try:
                original = str(payload["timestamp"])
                candidate = (
                    f"{original[:-1]}+00:00"
                    if original.endswith("Z")
                    else original
                )
                timestamp = datetime.fromisoformat(candidate) + timedelta(seconds=1)
                payload["timestamp"] = timestamp.astimezone(timezone.utc).isoformat().replace(
                    "+00:00",
                    "Z",
                )
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                raise CLIError(
                    f"could not alter timestamp in block {block_index}: {exc}"
                ) from exc
        elif field == "metadata":
            metadata = payload.get("metadata")
            if not isinstance(metadata, dict):
                metadata = {}
            metadata = dict(metadata)
            metadata["vaultguard_tamper_demo"] = True
            payload["metadata"] = metadata
        else:
            raise CLIError(f"unsupported tamper field: {field}")

        try:
            altered_payload = canonical_json(payload)
        except (TypeError, ValueError) as exc:
            raise CLIError(f"could not canonicalize tampered payload: {exc}") from exc

        connection.execute(
            f'DROP TRIGGER "{BLOCKS_NO_UPDATE_TRIGGER}"'
        )
        connection.execute(
            f"""
            UPDATE {BLOCKS_TABLE}
            SET payload_json = ?
            WHERE block_index = ?
            """,
            (altered_payload, block_index),
        )
        connection.commit()
    except sqlite3.Error as exc:
        if connection.in_transaction:
            connection.rollback()
        raise CLIError(f"tamper demonstration failed: {exc}") from exc
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        raise
    finally:
        connection.close()


def _seed_ephemeral_ledger(
    ledger: SQLiteLedger,
    *,
    count: int,
    actor: str,
    action: str,
) -> None:
    base_time = datetime.now(timezone.utc)
    for index in range(count):
        ledger.append(
            AuditPayload(
                timestamp=base_time + timedelta(seconds=index),
                actor=f"{actor}-demo-{index}",
                action=action,
                metadata={
                    "purpose": "vaultguard-tamper-demo",
                    "sequence": index,
                },
            )
        )


def _run_tamper_demo(
    database_path: str,
    secret_key: str,
    timeout: float,
    *,
    index: int,
    field: str,
    ephemeral: bool,
    count: int | None,
    actor: str,
    action: str,
) -> tuple[dict[str, object], bool]:
    with SQLiteLedger(
        database=database_path,
        secret_key=secret_key,
        timeout=timeout,
    ) as ledger:
        if ephemeral:
            block_count = count if count is not None else index + 1
            if block_count <= index:
                raise CLIError(
                    "ephemeral demo block count must be greater than --index"
                )
            try:
                _seed_ephemeral_ledger(
                    ledger,
                    count=block_count,
                    actor=actor,
                    action=action,
                )
            except (ValidationError, ValueError, TypeError) as exc:
                raise CLIError(f"invalid ephemeral demo configuration: {exc}") from exc

        before = ledger.verify_chain_integrity()
        if not before.is_valid:
            raise CLIError(
                f"ledger is already invalid; refusing tamper demo: {before.message}"
            )

        _tamper_database(
            database_path,
            index,
            field,
            timeout,
        )
        after = ledger.verify_chain_integrity()

    is_memory_database = database_path == ":memory:" or (
        _is_sqlite_uri(database_path)
        and "mode=memory" in database_path.lower()
    )
    if is_memory_database:
        final_result = after
    else:
        # Reopening also restores a trigger intentionally removed by the demo.
        with SQLiteLedger(
            database=database_path,
            secret_key=secret_key,
            timeout=timeout,
        ) as reopened:
            final_result = reopened.verify_chain_integrity()

    before_data = before.model_dump(mode="json")
    after_data = final_result.model_dump(mode="json")
    detected = (
        not final_result.is_valid
        and final_result.violation_index == index
    )

    summary: dict[str, object] = {
        "status": "tamper_detected" if detected else "tamper_not_detected",
        "database": database_path,
        "ephemeral": ephemeral,
        "index": index,
        "tampered_index": index,
        "field": field,
        "before": before_data,
        "after": after_data,
        "before_valid": before.is_valid,
        "after_valid": final_result.is_valid,
        "valid_before": before.is_valid,
        "valid_after": final_result.is_valid,
        "detected": detected,
        "violation_index": final_result.violation_index,
        "message": final_result.message,
    }
    return summary, detected


def _tamper_demo_command(args: argparse.Namespace) -> int:
    secret_key = _resolve_secret_key(args)
    timeout = _resolve_timeout(args)

    if args.ephemeral:
        with TemporaryDirectory(prefix="vaultguard-demo-") as directory:
            database_path = str(Path(directory) / "vaultguard-demo.db")
            summary, detected = _run_tamper_demo(
                database_path,
                secret_key,
                timeout,
                index=args.index,
                field=args.field,
                ephemeral=True,
                count=args.count,
                actor=args.actor,
                action=args.action,
            )
    else:
        database_path = _resolve_database(args)
        summary, detected = _run_tamper_demo(
            database_path,
            secret_key,
            timeout,
            index=args.index,
            field=args.field,
            ephemeral=False,
            count=args.count,
            actor=args.actor,
            action=args.action,
        )

    if _wants_json(args):
        print(canonical_json(summary))
    else:
        print("Tamper demonstration: SUCCESS" if detected else "FAILED")
        print(f"Database: {summary['database']}")
        print(f"Tampered block index: {args.index}")
        print(
            "Before: "
            f"{'VALID' if summary['before_valid'] else 'INVALID'}"
        )
        print(
            "After: "
            f"{'VALID' if summary['after_valid'] else 'INVALID'}"
        )
        print(f"Violation index: {summary['violation_index']}")
        print(f"Message: {summary['message']}")

    return EXIT_SUCCESS if detected else EXIT_INTEGRITY_FAILURE


def main(argv: Sequence[str] | None = None) -> int:
    """Execute the VaultGuard CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "append":
            return _append_command(args)
        if args.command == "verify":
            return _verify_command(args)
        if args.command == "tamper-demo":
            return _tamper_demo_command(args)
        raise CLIError(f"unknown command: {args.command}")
    except CLIError as exc:
        print(f"vaultguard: error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except StorageError as exc:
        print(f"vaultguard: storage error: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY_FAILURE
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"vaultguard: error: {exc}", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except KeyboardInterrupt:
        print("vaultguard: interrupted", file=sys.stderr)
        return 130