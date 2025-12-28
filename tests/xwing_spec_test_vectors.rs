//! Tests using official X-Wing specification test vectors
//! These vectors validate that our implementation correctly follows the X-Wing draft-09 specification

use pq_xwing_kem::xwing768::{generate_keypair, EncapsulationKey};
use rand_core::OsRng;
use serde::Deserialize;
use sha3::{digest::{ExtendableOutput, XofReader}, Shake128};
use std::fs;

#[derive(Deserialize, Debug)]
struct TestVector {
    seed: String,
    eseed: String,
    ss: String,
    sk: String,
    pk: String,
    ct: String,
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn test_official_xwing_test_vectors() {
    // Load official test vectors from the JSON file
    let test_vectors_json = fs::read_to_string("tests/test-vectors.json")
        .expect("Failed to read test vectors file");
    let test_vectors: Vec<TestVector> = serde_json::from_str(&test_vectors_json)
        .expect("Failed to parse test vectors JSON");

    // Generate expected test vectors using the same SHAKE128 approach as the Python reference
    let mut h = Shake128::default();
    let mut reader = h.finalize_xof();

    for (i, expected_vector) in test_vectors.iter().enumerate() {
        println!("Testing vector {}", i + 1);

        // Generate seed and eseed using SHAKE128 (same as Python reference)
        let mut seed = [0u8; 32];
        reader.read(&mut seed);
        let mut eseed = [0u8; 64];
        reader.read(&mut eseed);

        // Verify seed matches expected
        let expected_seed = hex_to_bytes(&expected_vector.seed);
        assert_eq!(seed.as_slice(), expected_seed.as_slice(),
                  "Seed mismatch for vector {}", i + 1);

        // Generate keypair from seed (deterministic)
        let enc_key = EncapsulationKey::from_seed(&seed);

        // Get the generated public key bytes
        let pk_bytes = enc_key.to_bytes();

        // Verify public key matches expected
        let expected_pk = hex_to_bytes(&expected_vector.pk);
        assert_eq!(pk_bytes.as_slice(), expected_pk.as_slice(),
                  "Public key mismatch for vector {}", i + 1);

        // TODO: Once we implement deterministic encapsulation, we can test the full flow
        // For now, we verify that our key generation is correct
    }
}

#[test]
fn test_keypair_generation_sizes() {
    // Test basic size requirements without using external test vectors

    // Test deterministic key generation
    let seed = [0u8; 32];
    let enc_key = EncapsulationKey::from_seed(&seed);

    // X-Wing 768: ML-KEM-768 PK (1184) + X25519 PK (32) = 1216 bytes
    assert_eq!(enc_key.to_bytes().len(), 1184 + 32, "Public key size incorrect");

    // Test public key getters
    assert_eq!(enc_key.pk_m().len(), 1184, "ML-KEM public key size incorrect");
    assert_eq!(enc_key.pk_x().to_bytes().len(), 32, "X25519 public key size incorrect");
}

#[test]
fn test_xwing_spec_compliance() {
    // Test basic compliance with X-Wing specification requirements

    // Test key sizes
    let (sk, pk) = generate_keypair(&mut OsRng).unwrap();

    // X-Wing 768: ML-KEM-768 (1184) + X25519 (32) = 1216 bytes
    assert_eq!(pk.to_bytes().len(), 1184 + 32, "Public key size incorrect");

    // X-Wing 768: ML-KEM-768 CT (1088) + X25519 CT (32) = 1120 bytes
    let (ct, ss) = pk.encapsulate(&mut OsRng).unwrap();
    assert_eq!(ct.to_bytes().len(), 1088 + 32, "Ciphertext size incorrect");

    // Shared secret should be 32 bytes
    assert_eq!(ss.len(), 32, "Shared secret size incorrect");

    // Test decapsulation
    let ss_decap = sk.decapsulate(&ct).unwrap();
    assert_eq!(ss, ss_decap, "Decapsulation failed");
}
