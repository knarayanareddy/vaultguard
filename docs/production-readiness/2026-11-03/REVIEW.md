# VaultGuard review

## Scope and verdict

Python ledger implementation at `c61cc8de5444287cdaaaedd8b3fa77c749a417ac`. The snapshot samples `README.md:1-6`, `pyproject.toml:1-26`, `vaultguard/__main__.py:1-7` and the first 220 lines of each of two longer test files. Engine, storage, CLI and model implementations were not sampled. No code, tests, dependency installation or operational checks were run. [Plan](REMEDIATION_PLAN.md).

## Architecture and product boundary

The package exposes `vaultguard.cli:main` as a console script ([pyproject.toml:22-23](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/pyproject.toml#L22-L23)) and through `python -m vaultguard`. The complete tree lists an engine, models and storage module; their actual behavior is uninspected. README describes SHA-256 chaining and HMAC-SHA256 for high-stakes audit events ([README.md:3-6](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/README.md#L3-L6)).

## Findings ledger

- **VG-1 — High, confirmed claim limitation:** README calls the trail `immutable` and asserts `Any historical alteration invalidates` the chain ([README.md:6](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/README.md#L6)). HMAC is symmetric: anyone holding the shared key can produce valid MACs, and a chain alone cannot establish that its tail was not deleted or an entire chain replaced without an independently trusted checkpoint. This is a limitation of the stated design, not a demonstrated exploit of uninspected code. State the threat model and use independently protected checkpoints and key controls.
- **VG-2 — High, unverified risk:** the tree includes `vaultguard/storage.py`, but its contents were not sampled. Atomic appends, competing writers, crash consistency, durability and recovery are essential to a ledger and cannot be inferred from filenames or unit tests. Verify with concurrency and fault injection.
- **VG-3 — Medium, confirmed static:** [`pyproject.toml:10-19`](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/pyproject.toml#L10-L19) declares only lower-bound runtime and dev dependencies. Reproducibility and automated enforcement are therefore not established from the sampled manifest alone.

## Five disciplines

- **Correctness:** sampled engine assertions cover canonical serialization output ([tests/test_engine.py:61-79](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/tests/test_engine.py#L61-L79)), independent SHA-256 payload hashing ([tests/test_engine.py:94-107](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/tests/test_engine.py#L94-L107)) and block-hash derivation from index plus parent hash ([tests/test_engine.py:165-183](https://github.com/knarayanareddy/vaultguard/blob/c61cc8de5444287cdaaaedd8b3fa77c749a417ac/tests/test_engine.py#L165-L183)). Implementation, whole-chain verification, key lifecycle and recovery behavior were not examined.
- **Testing:** model and engine test files exist but were only partially sampled. No storage or CLI test file is listed. No suite was run, so coverage and failure sensitivity are unknown.
- **DevOps:** key provisioning, rotation, durable storage, backup, external checkpointing and restore have no observed operational implementation. No deployed service is evidenced.
- **OWASP/security:** no web auth surface is evidenced; CLI access control and key custody are unverified. Assess injection through event data, secret leakage, dependencies, retention and access to sensitive audit records. HMAC integrity is not confidentiality or public non-repudiation.
- **UI/UX:** this is a CLI/library rather than an observed web UI. Error clarity, verification output and accessible terminal behavior were not tested.

## Production blockers and owner questions

Owner must define attacker capabilities, key custody/rotation, checkpoint authority, retention, writer concurrency, operational environment and recovery objectives. Do not rely on the ledger as immutable evidence until these are verified. Snapshot boundaries are the source ranges above; `SPEC.md`, engine, storage, CLI and unsampled test portions remain unread. No runtime, negative tampering test, backup, restore or external audit was performed.

## Evidence inventory and limitations

Inspected materialized sources: `README.md:1-6`, `pyproject.toml:1-26`, `vaultguard/__main__.py:1-7`, `tests/test_engine.py:1-220` and `tests/test_models.py:1-220` from `evidence/vaultguard/numbered-sources/`. Tree metadata in `evidence/vaultguard/snapshot.json:16-29` lists the captured revision paths used to bound this review; that captured tree includes `README.md`, `SPEC.md`, `pyproject.toml`, `tests/*` and `vaultguard/*`, and does not list a lockfile or `.github/workflows` path.

NOT RUN: package install, CLI invocation, storage fault injection, concurrent-writer tests, dependency resolution, CI workflows, checkpoint publication, backup, restore and any external audit. The absence of an issue in unread implementation files is not evidence of safety.
