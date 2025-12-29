// src/error.rs

//! Error types for xwing-kem operations.

use thiserror::Error;

/// Errors that can occur during xwing-kem operations.
#[derive(Error, Debug, Clone)]
pub enum Error {
    /// The encapsulation key has an invalid length.
    #[error("Invalid encapsulation key length")]
    InvalidEncapsulationKeyLength,

    /// The ciphertext has an invalid length.
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,

    /// The decapsulation key has an invalid length.
    #[error("Invalid decapsulation key length")]
    InvalidDecapsulationKeyLength,

    /// Failed to perform ML-KEM encapsulation.
    #[error("ML-KEM encapsulation failed")]
    MlkemEncapsulateError,

    /// Failed to perform ML-KEM decapsulation.
    #[error("ML-KEM decapsulation failed")]
    MlkemDecapsulateError,

    /// Failed to compute X25519 Diffie-Hellman shared secret.
    #[error("X25519 Diffie-Hellman failed")]
    X25519DhError,

    /// Invalid X25519 public key format.
    #[error("Invalid X25519 public key")]
    InvalidX25519PublicKey,

    /// Failed to compute X448 Diffie-Hellman shared secret.
    #[error("X448 Diffie-Hellman failed")]
    X448DhError,

    /// Invalid X448 public key format.
    #[error("Invalid X448 public key")]
    InvalidX448PublicKey,

    /// Invalid ML-KEM public key format.
    #[error("Invalid ML-KEM public key")]
    InvalidMlkemPublicKey,

    /// Invalid ML-KEM ciphertext format.
    #[error("Invalid ML-KEM ciphertext")]
    InvalidMlkemCiphertext,

    /// Key generation failed.
    #[error("Key generation failed")]
    KeyGenerationError,

    /// Array size conversion failed.
    #[error("Array size conversion failed")]
    ArraySizeError,
}

/// Type alias for results in xwing-kem.
pub type Result<T> = core::result::Result<T, Error>;
