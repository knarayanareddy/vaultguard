# VaultGuard

**Tamper-evident cryptographically signed append-only audit ledger with SHA-256 hash chaining.**

## Core Mission
Provide an immutable, mathematically verifiable audit trail for high-stakes operational events (key rotations, administrative overrides, data mutations). Every block is linked via SHA-256 parent hash pointers and signed with HMAC-SHA256. Any historical alteration invalidates the cryptographic chain.
