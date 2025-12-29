// tests/kat_tests.rs
use pq_xwing_kem::xwing768::{DecapsulationKey, EncapsulationKey};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct TestVector {
    #[serde(deserialize_with = "hex::serde::deserialize")]
    seed: [u8; 32],
    #[serde(deserialize_with = "hex::serde::deserialize")]
    eseed: [u8; 64],
    #[serde(deserialize_with = "hex::serde::deserialize")]
    ss: [u8; 32],
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pk: Vec<u8>,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    ct: Vec<u8>,
}

#[test]
fn test_official_kat_vectors() {
    let json =
        fs::read_to_string("tests/test-vectors.json").expect("Failed to read test-vectors.json");
    let vectors: Vec<TestVector> =
        serde_json::from_str(&json).expect("Failed to parse test vectors");

    for (i, vec) in vectors.iter().enumerate() {
        println!("Testing vector {}", i);

        // 1. Generate key pair from seed
        let pk = EncapsulationKey::from_seed(&vec.seed);
        let sk = DecapsulationKey::from_seed(&vec.seed);

        // 2. Check public key matches
        assert_eq!(
            pk.to_bytes().as_slice(),
            vec.pk.as_slice(),
            "Public key mismatch in vector {}",
            i
        );

        // 3. Deterministic encapsulation
        let (ct, ss_sender) = pk.encapsulate_derand(&vec.eseed);

        // 4. Check ciphertext and shared secret
        assert_eq!(
            ct.to_bytes().as_slice(),
            vec.ct.as_slice(),
            "Ciphertext mismatch in vector {}",
            i
        );
        assert_eq!(
            ss_sender, vec.ss,
            "Shared secret mismatch (sender) in vector {}",
            i
        );

        // 5. Decapsulation round-trip
        let ss_receiver = sk.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_receiver, vec.ss,
            "Shared secret mismatch (receiver) in vector {}",
            i
        );
    }
}

