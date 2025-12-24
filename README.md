# pq-xwing-kem

**⚠️ WARNING: This crate is under active development and is not suitable for production use. It may contain security vulnerabilities. Use at your own risk.**

Post-quantum hybrid X-Wing Key Encapsulation Mechanism (all ML-KEM variants + X25519).

This crate attempts to implement the X-Wing hybrid KEM as described in the [X-Wing: general-purpose hybrid post-quantum KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

**Current status (v0.0.1 placeholder)**:  
Active development in progress. Functional proof-of-concept implementation exists, but it is **not yet security-hardened** (constant-time guarantees, full fuzzing, formal verification, or external audit pending).

**Do not use in production yet.**

Planned improvements:
- Full constant-time operations
- Extensive testing and fuzzing
- Benchmarks and documentation
- no-std support

See the repository for ongoing work: https://github.com/Slurp9187/pq-xwing-kem
