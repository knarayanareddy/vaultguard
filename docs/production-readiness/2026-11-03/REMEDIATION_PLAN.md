# VaultGuard remediation plan

Proposed only; see [review](REVIEW.md). Finding IDs refer to that review. Any commands or checks below are future verification work, not evidence that they were run during this documentation pass.

## Phase map with entry and exit criteria

| Phase | Entry criteria | Exit criteria | Tasks | Discipline focus |
|---|---|---|---|---|
| 0. Baseline and reproduction | Owner names security and operations owners; isolated test data and environment are available | Full implementation paths are inspected, current guarantees are written down, and any reproduced gaps are distinguished from static-only concerns | VG-T1 | correctness, security, operations |
| 1. Security and correctness controls | VG-T1 complete; owner approves threat model scope | Integrity, checkpoint and storage guarantees are implemented or narrowed to match reality; README/SPEC claims match the actual trust model | VG-T2 | correctness, OWASP/security |
| 2. Meaningful automation | VG-T2 complete | Negative tests fail on deliberate breakage; dependency and CI policy is defined without lowering gates | VG-T3 | testing, dependency integrity |
| 3. Deployment and recovery | VG-T3 complete; owner selects storage and release target | Restore, rollback, key rotation handling and checkpoint recovery are observed against stated objectives | VG-T4 | DevOps/operations |
| 4. CLI UX and accessibility | VG-T3 complete; candidate verification and error flows exist | Operators can understand verification failures and recovery status in terminal usage without relying on unstated tribal knowledge | VG-T5 | UI/UX for CLI surfaces |
| 5. Independent acceptance | VG-T4 and VG-T5 evidence is complete | Independent reviewer repeats negative integrity and recovery checks, records residual risk, and either rejects or conditionally accepts release | VG-T6 | all five disciplines |

## Task dependency map

| Task | Depends on | Unlocks | Why the dependency exists |
|---|---|---|---|
| VG-T1 | owner names security and operations owners | VG-T2, VG-T3 | Later fixes and tests need an agreed trust model and inspected full code paths, not README assumptions |
| VG-T2 | VG-T1 and owner approval of guarantees | VG-T3, VG-T4, VG-T5 | Automation, recovery and operator messaging must validate the implemented integrity contract |
| VG-T3 | VG-T2 | VG-T4, VG-T5, VG-T6 | Recovery and acceptance need tests that fail when integrity controls are deliberately broken |
| VG-T4 | VG-T2, VG-T3 and owner-selected platform/objectives | VG-T6 | Independent acceptance needs observed restore and rollback evidence |
| VG-T5 | VG-T2, VG-T3 | VG-T6 | Independent acceptance should inspect the real CLI verification and failure experience |
| VG-T6 | VG-T4, VG-T5 | release decision | Final acceptance depends on both technical controls and observed operational behavior |

Dependency summary: `VG-T1 -> VG-T2 -> VG-T3`; `VG-T2 + VG-T3 -> VG-T4`; `VG-T2 + VG-T3 -> VG-T5`; `VG-T4 + VG-T5 -> VG-T6`.

### VG-T1 — Establish the real trust and storage baseline (VG-1, VG-2)

**Prerequisite:** owner names security and operations owners. **Observed paths:** `README.md`, `SPEC.md`, `vaultguard/engine.py`, `vaultguard/storage.py`, `vaultguard/cli.py`, `vaultguard/models.py`.

1. Read the full implementation and map what actually enforces canonical encoding, sequence rules, HMAC signing, append semantics, verification, and storage writes.
2. Write the attacker model for key holders, storage operators, verifiers and backup/restore operators, including what happens if the latest checkpoint or tail is removed.
3. Reconcile README and SPEC wording with the inspected code so unsupported claims about immutability or mathematical verifiability are narrowed before implementation work continues.

**Deliverable:** evidence-backed trust, storage and claim-boundary baseline. **Verification:** an independent reviewer can point to where tail deletion, chain replacement, key compromise and storage corruption are detected, or can see those cases explicitly documented as out of scope. **DoD:**
- [ ] HMAC limitations are distinguished from public-signature guarantees.
- [ ] Checkpoint authority, retention and verifier trust are explicitly named.
- [ ] Uninspected assumptions are removed from README/SPEC or marked as planned.

### VG-T2 — Implement bounded integrity and durability controls (VG-1, VG-2)

**Prerequisite:** VG-T1 and owner approval of the target threat model. **Observed paths:** `vaultguard/engine.py`, `vaultguard/storage.py`, `vaultguard/models.py`; any new operations notes are **proposed paths**.

1. Implement the approved integrity contract for canonical payload encoding, block sequencing, block verification and checkpoint comparison.
2. Add storage behavior appropriate to the chosen backend for atomic append, competing writers, interrupted writes and restart recovery, instead of assuming single-writer success.
3. Define key provisioning, rotation, revocation and logging rules so secrets are not written into ledger data, terminal output or recovery artifacts.

**Deliverable:** narrowed and implemented integrity/durability contract. **Verification:** deliberate altered-block, tail-truncation, stale-checkpoint, wrong-key and interrupted-write scenarios are exercised against the selected backend and produce the expected failure mode. **DoD:**
- [ ] Tampering is detected only within explicitly stated assumptions.
- [ ] Crash and concurrent-writer behavior is specified and tested.
- [ ] Sensitive key-handling and event-retention rules are documented.

### VG-T3 — Add meaningful automation and reproducibility gates (VG-2, VG-3)

**Prerequisite:** VG-T2. **Observed paths:** `tests/test_engine.py`, `tests/test_models.py`, `pyproject.toml`; storage/CLI tests, lock material and CI workflow are **proposed if absent**.

1. Add independent cryptographic vectors and negative tests for wrong keys, malformed blocks, replaced chains, truncated tails, key rotation and verifier/checkpoint mismatch.
2. Add storage and CLI tests for concurrent append attempts, interrupted writes, corrupted records and actionable verification output.
3. Define reproducible dependency and CI policy using whatever manifest and workflow structure the repo actually adopts, without inventing a current lockfile or pretending existing automation is already present.

**Deliverable:** regression suite and reproducibility policy. **Verification:** deliberately breaking hash linkage, checkpoint validation or storage atomicity makes the corresponding test fail; dependency resolution policy is recorded rather than implied. **DoD:**
- [ ] Negative tests fail on deliberately broken integrity behavior.
- [ ] Storage and CLI failure cases are covered by non-tautological tests.
- [ ] Dependency and CI policy is explicit about current limits and future enforcement.

### VG-T4 — Prove deployment and recovery behavior (VG-2; preventive)

**Prerequisite:** VG-T3; owner approves deployment target, retention, RPO/RTO and checkpoint location. **Observed paths:** `vaultguard/cli.py`, `vaultguard/storage.py`; release/recovery runbook path is **proposed**.

1. Inventory what must be backed up and restored: ledger files, checkpoints, configuration, key references and operator instructions, while excluding raw secret material from routine artifacts.
2. Rehearse restore of a synthetic ledger plus independently stored checkpoint into an isolated environment and verify the restored chain state before any new append occurs.
3. Record release, rollback and rotation procedures for the chosen packaging/distribution model, including how to quarantine or preserve suspect ledger history during incident response.

**Deliverable:** observed recovery and rollback runbook. **Verification:** an operator other than the implementer restores the synthetic ledger and checkpoint, confirms expected verification output, and can roll back to a known-good artifact without rewriting production history. **DoD:**
- [ ] Restore outcome is measured against owner objectives.
- [ ] Checkpoint recovery is observed, not assumed.
- [ ] Rollback preserves evidence and does not silently rewrite the ledger.

### VG-T5 — Validate CLI verification UX and accessibility (preventive)

**Prerequisite:** VG-T3. **Observed paths:** `vaultguard/cli.py`; terminal guidance and operator docs are **proposed paths**.

1. Review the actual CLI verification, append and failure paths for clear exit codes, concise error messages and distinguishable success versus warning versus failure output.
2. Exercise terminal-only operator flows for corrupted ledgers, wrong keys, missing checkpoints and interrupted recovery so failure states are understandable under time pressure.
3. Document expected terminal behavior, keyboard-only usage and any color/formatting fallback needed so the tool remains usable when rich formatting is unavailable or inaccessible.

**Deliverable:** operator-facing CLI verification guidance and any required UX fixes. **Verification:** a reviewer unfamiliar with the code can follow the docs to interpret success and failure outputs for the main integrity and recovery cases. **DoD:**
- [ ] Verification output clearly separates pass, fail and unknown states.
- [ ] Error handling is documented for missing key/checkpoint and corrupt-ledger cases.
- [ ] Accessibility limits of the terminal experience are recorded if they remain unresolved.

### VG-T6 — Independent acceptance (all findings and preventive work)

**Prerequisite:** VG-T4 and VG-T5, with complete evidence from VG-T1 through VG-T5. **Observed paths:** changed source/tests above; acceptance record path is **proposed**.

1. Have a reviewer independent of implementation inspect the final diff and map each accepted claim back to the live code path and its negative test.
2. Repeat altered-block, wrong-key, tail-truncation, interrupted-write and restore checks in a clean environment; deliberately break one control to prove the regression suite detects it.
3. Record residual risk, unsupported platforms, operational assumptions and owner decisions, then approve or reject release based on observed evidence rather than test counts.

**Deliverable:** independent acceptance record with exact revision and environment. **Verification:** the record includes commands or procedures actually used, negative-control outcomes and restore observations tied to the candidate artifact. **DoD:**
- [ ] Independent reviewer confirms findings are closed or explicitly accepted.
- [ ] At least one deliberate broken-control test is shown to fail.
- [ ] Remaining operational assumptions are owned in writing.

## Production acceptance checklist

- [ ] README/SPEC claims match the implemented trust model; no unsupported “immutable” or “mathematically verifiable” claim remains.
- [ ] Integrity, truncation, chain-replacement and wrong-key behavior is demonstrated within a documented threat model.
- [ ] Storage semantics for crash recovery and competing writers are observed on the chosen backend.
- [ ] Dependency/CI policy is documented honestly, including any current absence of lockfiles or workflows.
- [ ] Restore, rollback and checkpoint recovery are observed on synthetic data before release.
- [ ] CLI verification and failure output is understandable to an operator who did not implement the feature.
- [ ] Independent acceptance evidence names the exact revision, environment and negative-control result.

## Changes requiring owner approval

- Threat-model scope, including who may hold HMAC keys and who operates checkpoints.
- Storage backend choice, concurrency model and acceptable recovery objectives.
- Any README/SPEC wording that changes product claims or customer-facing guarantees.
- Packaging, distribution, signing, retention and backup locations.
- Residual risks accepted without remediation.

## Release and rollback policy

Do not release on test-count claims alone. Release only after VG-T6 evidence exists for the candidate revision. If a release candidate fails integrity, checkpoint, restore or operator-verification checks, stop shipment, preserve the suspect ledger and artifacts for investigation, rotate any exposed key material under the approved process, and roll back to the last independently verified artifact and configuration without rewriting historical records.
