//! Unit tests for xwing1024.

use pq_xwing_kem::xwing1024::{
    generate_keypair, Ciphertext, EncapsulationKey, XWING1024_CIPHERTEXT_SIZE,
    XWING1024_ENCAPSULATION_KEY_SIZE,
};
use rand_core::OsRng;

#[test]
fn test_generate_keypair() {
    let mut rng = OsRng;
    let (_sk, pk) = generate_keypair(&mut rng);

    assert_eq!(pk.to_bytes().len(), XWING1024_ENCAPSULATION_KEY_SIZE);
}

#[test]
fn test_encapsulation_decapsulation_roundtrip() {
    let mut rng = OsRng;
    let (sk, pk) = generate_keypair(&mut rng);

    let (ct, ss_encap) = pk.encapsulate();
    let ss_decap = sk.decapsulate(&ct);

    assert_eq!(ss_encap, ss_decap);
    assert_eq!(ct.to_bytes().len(), XWING1024_CIPHERTEXT_SIZE);
}

#[test]
fn test_encapsulation_key_serialization() {
    let mut rng = OsRng;
    let (_sk, pk) = generate_keypair(&mut rng);

    let pk_bytes = pk.to_bytes();
    let pk_restored = EncapsulationKey::from(&pk_bytes);

    assert_eq!(pk, pk_restored);
}

#[test]
fn test_ciphertext_serialization() {
    let mut rng = OsRng;
    let (_sk, pk) = generate_keypair(&mut rng);

    let (ct, _) = pk.encapsulate();
    let ct_bytes = ct.to_bytes();
    let ct_restored = Ciphertext::from(&ct_bytes);

    assert_eq!(ct, ct_restored);
}

#[test]
fn test_different_keys_produce_different_secrets() {
    let mut rng = OsRng;
    let (_sk1, pk1) = generate_keypair(&mut rng);
    let (_sk2, pk2) = generate_keypair(&mut rng);

    let (ct1, ss1) = pk1.encapsulate();
    let (ct2, ss2) = pk2.encapsulate();

    assert_ne!(ss1, ss2);
    assert_ne!(ct1, ct2);
}

#[test]
fn test_wrong_key_decapsulate_fails() {
    let mut rng = OsRng;
    let (_sk1, pk1) = generate_keypair(&mut rng);
    let (sk2, _pk2) = generate_keypair(&mut rng);

    let (ct, ss_encap) = pk1.encapsulate();
    let ss_decap = sk2.decapsulate(&ct);

    // Since it's hybrid, and ML-KEM decapsulates to random if wrong key,
    // but X25519 will give different ss_x, so overall different secret.
    assert_ne!(ss_encap, ss_decap);
}

#[test]
fn test_encapsulation_non_zero_ciphertext() {
    let mut rng = OsRng;
    let (_, pk) = generate_keypair(&mut rng);
    let (ct, _) = pk.encapsulate();
    // Ensure CT is not all zeros
    assert!(!ct.to_bytes().iter().all(|&b| b == 0));
}

#[test]
fn test_decapsulation_modified_ciphertext_fails() {
    let mut rng = OsRng;
    let (sk, pk) = generate_keypair(&mut rng);
    let (ct, ss_encap) = pk.encapsulate();
    // Modify the CT
    let mut modified_bytes = ct.to_bytes();
    modified_bytes[0] ^= 1; // Flip a bit
    let modified_ct = Ciphertext::from(&modified_bytes);
    let ss_decap = sk.decapsulate(&modified_ct);
    // Should produce different secret
    assert_ne!(ss_encap, ss_decap);
}

#[test]
fn test_ciphertext_size() {
    let mut rng = OsRng;
    let (_, pk) = generate_keypair(&mut rng);
    let (ct, _) = pk.encapsulate();
    assert_eq!(ct.to_bytes().len(), XWING1024_CIPHERTEXT_SIZE);
}
