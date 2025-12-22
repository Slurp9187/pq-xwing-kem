// src/lib.rs

//! # xwing
//!
//! X-Wing hybrid post-quantum KEM (ML-KEM-512/768/1024 + X25519)
//! using libcrux and x25519-dalek.
//!
//! Implements draft-connolly-cfrg-xwing-kem-09 specification.
//!
//! Currently provides:
//! - `xwing512`: ML-KEM-512 + X25519 variant
//! - `xwing768`: ML-KEM-768 + X25519 variant
//! - `xwing1024`: ML-KEM-1024 + X25519 variant

// #![no_std]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]

extern crate alloc;

pub mod combiner;
pub mod consts;
pub mod error;
pub mod xwing_kem_1024;
pub mod xwing_kem_512;
pub mod xwing_kem_768;

pub(crate) use combiner::combiner;
pub use xwing_kem_1024::{
    xwing1024_generate_keypair, XWING1024_CIPHERTEXT_SIZE, XWING1024_DECAPSULATION_KEY_SIZE,
    XWING1024_ENCAPSULATION_KEY_SIZE,
};
pub use xwing_kem_512::{
    xwing512_generate_keypair, XWING512_CIPHERTEXT_SIZE, XWING512_DECAPSULATION_KEY_SIZE,
    XWING512_ENCAPSULATION_KEY_SIZE,
};
pub use xwing_kem_768::{
    xwing768_generate_keypair, XWING768_CIPHERTEXT_SIZE, XWING768_DECAPSULATION_KEY_SIZE,
    XWING768_ENCAPSULATION_KEY_SIZE,
};

pub const XWING_DRAFT_VERSION: &str = "09";

pub use consts::{MASTER_SEED_SIZE, SHARED_SECRET_SIZE};
pub use error::{Error, Result};

pub type SharedSecret = [u8; SHARED_SECRET_SIZE];
