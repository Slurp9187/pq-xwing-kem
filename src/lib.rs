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
pub mod xwing1024;
pub mod xwing512;
pub mod xwing768;

pub(crate) use combiner::combiner;

pub const XWING_DRAFT_VERSION: &str = "09";

pub use consts::{MASTER_SEED_SIZE, SHARED_SECRET_SIZE};
pub use error::{Error, Result};

pub type SharedSecret = [u8; SHARED_SECRET_SIZE];
