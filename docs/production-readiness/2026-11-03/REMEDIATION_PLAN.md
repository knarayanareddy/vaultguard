# VaultGuard remediation plan

Proposed only; see [review](REVIEW.md). Dependencies: `VG-T1 → VG-T2 → VG-T3 → VG-T4`.

### VG-T1 — Define trust and storage model (VG-1, VG-2)
Prerequisite: owner names security and operations owners. Observed paths: `SPEC.md`, `vaultguard/engine.py`, `vaultguard/storage.py`, `vaultguard/cli.py`.
1. Read the full implementation and specify attacker access to storage, keys and verifier.
2. Trace canonical encoding, sequence enforcement, key use, append locking and failure handling.
3. Define independent checkpoint storage, key rotation, retention and acceptable tamper-detection guarantees; correct overbroad README claims.
Deliverable: threat model and evidence-backed contract. Verification: independent reviewer identifies how a removed tail or key compromise would be detected or explicitly remains undetectable.
- [ ] Guarantees and limitations distinguish HMAC from public signatures.
- [ ] Writer and checkpoint authority are explicitly specified.

### VG-T2 — Implement integrity and durability controls (VG-1, VG-2)
Prerequisite: VG-T1 and owner approval. Observed paths: `vaultguard/engine.py`, `vaultguard/storage.py`, `vaultguard/models.py`.
1. Enforce the approved sequence, canonicalization and authenticated checkpoint contract.
2. Add atomic append and safe concurrent-writer behavior appropriate to the selected storage backend.
3. Define secret provisioning, rotation and recovery without logging keys; document retained sensitive event fields.
Deliverable: bounded integrity and durability implementation. Verification: inject mid-write failure, concurrent writes, altered blocks and tail truncation against independent checkpoints.
- [ ] Tampering and truncation within the stated threat model are detected.
- [ ] Crash and concurrency behavior is explicitly verified.

### VG-T3 — Meaningful automation (VG-2, VG-3)
Prerequisite: VG-T2. Observed paths: `tests/test_engine.py`, `tests/test_models.py`, `pyproject.toml`; proposed storage/CLI tests and CI workflow.
1. Add independent fixed cryptographic vectors and tests for malformed records, wrong keys, chain replacement and key rotation.
2. Add storage and CLI tests for concurrent appends, interrupted writes and actionable verification failures.
3. Define locked dependency and CI policy; run reproducible tests and audit dependencies without reducing thresholds.
Deliverable: independent regression suite and reproducible checks. Verification: deliberately break hash linkage or checkpoint validation in isolation and confirm the relevant test fails.
- [ ] Negative tests fail on deliberately broken integrity checks.
- [ ] Clean dependency resolution and CI results are recorded.

### VG-T4 — Recovery and independent acceptance (preventive)
Prerequisite: VG-T3; owner approves key custody and recovery objectives. Observed paths: `vaultguard/cli.py`, `vaultguard/storage.py`; proposed operations documentation.
1. Exercise CLI error messages and verification output with operators, including accessible terminal use.
2. Restore a synthetic ledger and independently stored checkpoint to an isolated environment and verify expected sequence and integrity.
3. Independently review release artifact provenance, key access and rollback procedures on the candidate revision.
Deliverable: observed recovery and acceptance record. Verification: an independent operator confirms restored data, checkpoint and rollback to a verified artifact.
- [ ] Restore and checkpoint verification are observed.
- [ ] Owner approves remaining risks and operational responsibilities.

## Gate and approvals

Owner must approve threat model, key storage, access, retention, checkpoint authority and recovery objectives. Stop release if integrity, independent checkpoint or recovery evidence is missing. Roll back to a verified artifact without discarding or rewriting production ledger history.
