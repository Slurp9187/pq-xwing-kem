// src/lib.rs

//! # xwing
//!
//! X-Wing hybrid post-quantum KEM (ML-KEM-512/768/1024 + X25519)
//! using libcrux and x25519-dalek.
//!
//! Implements draft-connolly-cfrg-xwing-kem-09 specification.
//!
//! ## Security Properties
//!
/// This implementation provides the following security properties:
/// - **Constant-time operations**: All cryptographic operations execute in constant time to prevent
///   timing side-channel attacks. The underlying libraries (libcrux ML-KEM and x25519-dalek/x448) provide
///   verified constant-time implementations.
/// - **Memory safety**: Sensitive data is automatically zeroized when it goes out of scope using
///   `ZeroizeOnDrop`.
/// - **Input validation**: All public inputs are validated to prevent malformed data attacks.
/// - **Cryptographic validation**: ML-KEM keys and X25519/X448 public keys are validated for proper format
///   and cryptographic validity.
///
/// Currently provides:
/// - `mlkem1024x448`: ML-KEM-1024 + X448 variant
/// - `xwing512`: ML-KEM-512 + X25519 variant (not yet implemented)
/// - `xwing768`: ML-KEM-768 + X25519 variant
/// - `xwing1024`: ML-KEM-1024 + X25519 variant
// #![no_std]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]
extern crate alloc;

pub mod combiner;
pub mod consts;
pub mod error;
pub mod mlkem1024x25519;
pub mod mlkem1024x448;
pub mod mlkem768x25519;

pub(crate) use combiner::combiner;

pub const XWING_DRAFT_VERSION: &str = "09";

pub use consts::{MASTER_SEED_SIZE, SHARED_SECRET_SIZE};
pub use error::{Error, Result};

/// The shared secret produced by X-Wing KEM encapsulation or decapsulation.
///
/// This is a 32-byte array representing the hybrid post-quantum/classical symmetric key
/// derived from ML-KEM and X25519 components. It ensures type safety for the final output
/// of the scheme's cryptographic operations.
pub type SharedSecret = [u8; SHARED_SECRET_SIZE];
