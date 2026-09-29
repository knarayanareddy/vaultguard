# VaultGuard: Cryptographically Verifiable Tamper-Evident Audit Ledger

> **Constitutional Rule**: Immutable by construction. Any single-byte modification to payload, timestamp, or parent hash invalidates the cryptographic chain.

---

## 1. Executive Summary & Vision
High-assurance systems require tamper-evident logging for sensitive security events (administrative overrides, credential rotations, database migrations). Standard relational logs can be quietly updated or deleted by a compromised DBA or system administrator with write access.

**Job To Be Done**:
Ingest structured security audit events $\rightarrow$ compute canonical deterministic SHA-256 payload hash $\rightarrow$ chain each block to the cryptographic hash of its predecessor block (with genesis block prev_hash = "0" * 64) $\rightarrow$ sign the block with HMAC-SHA256 $\rightarrow$ persist to append-only SQLite storage $\rightarrow$ provide instantaneous whole-chain mathematical audit verification detecting insertions, deletions, or bit-flips.

---

## 2. Technical Stack & Dependencies
- **Primary Language**: Python 3.12
- **Data Models**: Pydantic v2 (strict validation, ISO-8601 UTC timestamps)
- **Cryptography**: Python standard library `hashlib` (SHA-256) and `hmac`
- **Storage**: SQLite (`vaultguard.db`) with append-only semantics and foreign-key / sequential index integrity
- **CLI**: Standard library `argparse` or `rich` for formatted tabular chain verification output
- **Testing**: pytest (100% pass on model validation, hash continuity, and deliberate tamper injections)

---

## 3. Project Architecture & File Tree
```
vaultguard/
├── __init__.py
├── models.py              # Pydantic models: AuditAction, AuditPayload, ChainBlock, VerificationResult
├── engine.py              # Hash-chain engine: canonical JSON, SHA-256 chaining, HMAC signatures
├── storage.py             # SQLite append-only ledger & chain verification traversal
├── cli.py                 # CLI interface: append, verify, tamper-demo
tests/
├── test_models.py         # Model schemas and timestamp validation
├── test_engine.py         # Hash chaining continuity & HMAC signature verification
├── test_storage.py        # Append-only persistence & tamper detection tests
└── test_cli.py            # CLI commands execution tests
```

---

## 4. Key Security Invariants & Acceptance Criteria

### Invariant 1: Canonical Serialization & Hash Continuity
- **Genesis Block**: Block index 0 must have `prev_hash = "0" * 64`.
- **Chaining Invariant**: For any block $N > 0$, `block[N].prev_hash == block[N-1].current_hash`.
- **Canonical Hash**: Payload hash must use RFC-8785 canonical JSON sorting (`sort_keys=True`, `separators=(',', ':')`) so key ordering variations never alter the computed SHA-256 hash.

### Invariant 2: Cryptographic Tamper Detection
- If any byte of an existing payload, timestamp, or actor in SQLite is altered, `verify_chain_integrity()` must return `is_valid = False` and identify the exact `violation_index` where the hash link broke.

---

## 5. Step-by-Step Implementation Checklist

### Phase 1: Core Domain Models & Cryptographic Engine
- [x] 1.1 Strict domain data models in `vaultguard/models.py` (`AuditAction`, `AuditPayload`, `ChainBlock`, `VerificationResult`)
- [ ] 1.2 Cryptographic hash-chaining engine in `vaultguard/engine.py` with canonical JSON serialization, SHA-256 hashing, and HMAC signatures

### Phase 2: Persistent Storage, Integrity Auditing & CLI
- [ ] 2.1 SQLite append-only storage in `vaultguard/storage.py` with chain verification and tamper detection
- [ ] 2.2 Command-line interface and tamper demonstration in `vaultguard/cli.py` (`append`, `verify`, `tamper-demo`)
