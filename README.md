# pq-xwing-kem

**🔒 Security-Hardened Implementation** - Post-quantum hybrid X-Wing Key Encapsulation Mechanism (ML-KEM-768/1024 + X25519).

This crate implements the X-Wing hybrid KEM as described in the [X-Wing: general-purpose hybrid post-quantum KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) specification (draft-connolly-cfrg-xwing-kem-09).

## Security Features

- ✅ **Cryptographically Correct**: Full compliance with X-Wing draft-09 specification
- ✅ **Constant-Time Operations**: Uses formally verified libcrux ML-KEM and audited x25519-dalek
- ✅ **Memory Safe**: Comprehensive zeroization of sensitive data with `ZeroizeOnDrop`
- ✅ **Input Validation**: Validates all public keys and cryptographic parameters
- ✅ **Pinned Dependencies**: All dependencies locked to specific versions for reproducible builds
- ✅ **Error Handling**: Proper `Result` types with no panic paths in critical operations

## Production Readiness

**Status**: Production-ready with appropriate security review and testing.

**Dependencies**: All cryptographic dependencies are pinned to stable, audited versions:
- `libcrux-ml-kem = "0.0.4"` (formally verified ML-KEM implementation)
- `x25519-dalek = "2.0.1"` (constant-time X25519)
- `sha3 = "0.10.8"` (constant-time SHA3)

## Usage

```rust
use pq_xwing_kem::xwing768::{generate_keypair, EncapsulationKey};
use rand_core::OsRng;

// Generate a keypair
let (decapsulation_key, encapsulation_key) = generate_keypair(&mut OsRng).unwrap();

// Encapsulate (sender side)
let (ciphertext, shared_secret) = encapsulation_key.encapsulate(&mut OsRng).unwrap();

// Decapsulate (receiver side)
let receiver_shared_secret = decapsulation_key.decapsulate(&ciphertext).unwrap();

assert_eq!(shared_secret, receiver_shared_secret);
```

## API Variants

- `xwing768`: ML-KEM-768 + X25519 (recommended for most applications)
- `xwing1024`: ML-KEM-1024 + X25519 (higher security level)

See the repository for ongoing work: https://github.com/Slurp9187/pq-xwing-kem
