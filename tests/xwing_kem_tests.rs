// xwing-kem/tests/unit_tests.rs

//! Unit tests for combiner and xwing_kem_1024 modules.

use rand_core::OsRng;
use xwing_kem::combiner::combiner as combiner_fn;
use xwing_kem::consts::SHARED_SECRET_SIZE;
use xwing_kem::xwing_kem_1024::{
    generate_keypair, Ciphertext, EncapsulationKey, CIPHERTEXT_SIZE, ENCAPSULATION_KEY_SIZE,
};
use xwing_kem::xwing_kem_512 as kem512;
use xwing_kem::xwing_kem_768 as kem768;

#[cfg(test)]
mod combiner_tests {
    use super::*;

    #[test]
    fn test_combiner_consistency() {
        let ss_m = [1u8; 32];
        let ss_x = [2u8; 32];
        let ct_x = [3u8; 32];
        let pk_x = [4u8; 32];

        let result1 = combiner_fn(&ss_m, &ss_x, &ct_x, &pk_x);
        let result2 = combiner_fn(&ss_m, &ss_x, &ct_x, &pk_x);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn test_combiner_different_inputs() {
        let ss_m = [1u8; 32];
        let ss_x = [2u8; 32];
        let ct_x = [3u8; 32];
        let pk_x = [4u8; 32];

        let result1 = combiner_fn(&ss_m, &ss_x, &ct_x, &pk_x);
        let result2 = combiner_fn(&ss_x, &ss_m, &pk_x, &ct_x); // swapped

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_combiner_includes_label() {
        // The label should ensure output differs from plain SHA3-256 of inputs
        let ss_m = [0u8; 32];
        let ss_x = [0u8; 32];
        let ct_x = [0u8; 32];
        let pk_x = [0u8; 32];

        use sha3::{Digest, Sha3_256};
        let plain_hash = Sha3_256::new()
            .chain_update(ss_m)
            .chain_update(ss_x)
            .chain_update(ct_x)
            .chain_update(pk_x)
            .finalize();
        let combined = combiner_fn(&ss_m, &ss_x, &ct_x, &pk_x);

        assert_ne!(plain_hash.as_slice(), combined.as_slice());
    }

    #[test]
    fn test_combiner_all_zero_inputs() {
        let ss_m = [0u8; 32];
        let ss_x = [0u8; 32];
        let ct_x = [0u8; 32];
        let pk_x = [0u8; 32];
        let result = combiner_fn(&ss_m, &ss_x, &ct_x, &pk_x);
        // Should still produce a non-zero hash due to the label
        assert!(!result.iter().all(|&b| b == 0));
        assert_eq!(result.len(), SHARED_SECRET_SIZE);
    }
}

#[cfg(test)]
mod xwing_kem_1024_tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let mut rng = OsRng;
        let (_sk, pk) = generate_keypair(&mut rng);

        assert_eq!(pk.to_bytes().len(), ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = generate_keypair(&mut rng);

        let (ct, ss_encap) = pk.encapsulate();
        let ss_decap = sk.decapsulate(&ct);

        assert_eq!(ss_encap, ss_decap);
        assert_eq!(ct.to_bytes().len(), CIPHERTEXT_SIZE);
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
        assert_eq!(ct.to_bytes().len(), CIPHERTEXT_SIZE);
    }
}

#[cfg(test)]
mod xwing_kem_512_tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let mut rng = OsRng;
        let (_sk, pk) = kem512::generate_keypair(&mut rng);

        assert_eq!(pk.to_bytes().len(), kem512::ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = kem512::generate_keypair(&mut rng);

        let (ct, ss_encap) = pk.encapsulate(&mut rng);
        let ss_decap = sk.decapsulate(&ct);

        assert_eq!(ss_encap, ss_decap);
        assert_eq!(ct.to_bytes().len(), kem512::CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_encapsulation_key_serialization() {
        let mut rng = OsRng;
        let (_sk, pk) = kem512::generate_keypair(&mut rng);

        let pk_bytes = pk.to_bytes();
        let pk_restored = kem512::EncapsulationKey::from(&pk_bytes);

        assert_eq!(pk, pk_restored);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let mut rng = OsRng;
        let (_sk, pk) = kem512::generate_keypair(&mut rng);

        let (ct, _) = pk.encapsulate(&mut rng);
        let ct_bytes = ct.to_bytes();
        let ct_restored = kem512::Ciphertext::from(&ct_bytes);

        assert_eq!(ct, ct_restored);
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let mut rng = OsRng;
        let (_sk1, pk1) = kem512::generate_keypair(&mut rng);
        let (_sk2, pk2) = kem512::generate_keypair(&mut rng);

        let (ct1, ss1) = pk1.encapsulate(&mut rng);
        let (ct2, ss2) = pk2.encapsulate(&mut rng);

        assert_ne!(ss1, ss2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_decapsulate_fails() {
        let mut rng = OsRng;
        let (_sk1, pk1) = kem512::generate_keypair(&mut rng);
        let (sk2, _pk2) = kem512::generate_keypair(&mut rng);

        let (ct, ss_encap) = pk1.encapsulate(&mut rng);
        let ss_decap = sk2.decapsulate(&ct);

        // Since it's hybrid, and ML-KEM decapsulates to random if wrong key,
        // but X25519 will give different ss_x, so overall different secret.
        assert_ne!(ss_encap, ss_decap);
    }

    #[test]
    fn test_encapsulation_non_zero_ciphertext() {
        let mut rng = OsRng;
        let (_, pk) = kem512::generate_keypair(&mut rng);
        let (ct, _) = pk.encapsulate(&mut rng);
        // Ensure CT is not all zeros
        assert!(!ct.to_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_decapsulation_modified_ciphertext_fails() {
        let mut rng = OsRng;
        let (sk, pk) = kem512::generate_keypair(&mut rng);
        let (ct, ss_encap) = pk.encapsulate(&mut rng);
        // Modify the CT
        let mut modified_bytes = ct.to_bytes();
        modified_bytes[0] ^= 1; // Flip a bit
        let modified_ct = kem512::Ciphertext::from(&modified_bytes);
        let ss_decap = sk.decapsulate(&modified_ct);
        // Should produce different secret
        assert_ne!(ss_encap, ss_decap);
    }

    #[test]
    fn test_ciphertext_size() {
        let mut rng = OsRng;
        let (_, pk) = kem512::generate_keypair(&mut rng);
        let (ct, _) = pk.encapsulate(&mut rng);
        assert_eq!(ct.to_bytes().len(), kem512::CIPHERTEXT_SIZE);
    }
}

#[cfg(test)]
mod xwing_kem_768_tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let mut rng = OsRng;
        let (_sk, pk) = kem768::generate_keypair(&mut rng);

        assert_eq!(pk.to_bytes().len(), kem768::ENCAPSULATION_KEY_SIZE);
    }

    #[test]
    fn test_encapsulation_decapsulation_roundtrip() {
        let mut rng = OsRng;
        let (sk, pk) = kem768::generate_keypair(&mut rng);

        let (ct, ss_encap) = pk.encapsulate(&mut rng);
        let ss_decap = sk.decapsulate(&ct);

        assert_eq!(ss_encap, ss_decap);
        assert_eq!(ct.to_bytes().len(), kem768::CIPHERTEXT_SIZE);
    }

    #[test]
    fn test_encapsulation_key_serialization() {
        let mut rng = OsRng;
        let (_sk, pk) = kem768::generate_keypair(&mut rng);

        let pk_bytes = pk.to_bytes();
        let pk_restored = kem768::EncapsulationKey::from(&pk_bytes);

        assert_eq!(pk, pk_restored);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let mut rng = OsRng;
        let (_sk, pk) = kem768::generate_keypair(&mut rng);

        let (ct, _) = pk.encapsulate(&mut rng);
        let ct_bytes = ct.to_bytes();
        let ct_restored = kem768::Ciphertext::from(&ct_bytes);

        assert_eq!(ct, ct_restored);
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let mut rng = OsRng;
        let (_sk1, pk1) = kem768::generate_keypair(&mut rng);
        let (_sk2, pk2) = kem768::generate_keypair(&mut rng);

        let (ct1, ss1) = pk1.encapsulate(&mut rng);
        let (ct2, ss2) = pk2.encapsulate(&mut rng);

        assert_ne!(ss1, ss2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_decapsulate_fails() {
        let mut rng = OsRng;
        let (_sk1, pk1) = kem768::generate_keypair(&mut rng);
        let (sk2, _pk2) = kem768::generate_keypair(&mut rng);

        let (ct, ss_encap) = pk1.encapsulate(&mut rng);
        let ss_decap = sk2.decapsulate(&ct);

        // Since it's hybrid, and ML-KEM decapsulates to random if wrong key,
        // but X25519 will give different ss_x, so overall different secret.
        assert_ne!(ss_encap, ss_decap);
    }

    #[test]
    fn test_encapsulation_non_zero_ciphertext() {
        let mut rng = OsRng;
        let (_, pk) = kem768::generate_keypair(&mut rng);
        let (ct, _) = pk.encapsulate(&mut rng);
        // Ensure CT is not all zeros
        assert!(!ct.to_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_decapsulation_modified_ciphertext_fails() {
        let mut rng = OsRng;
        let (sk, pk) = kem768::generate_keypair(&mut rng);
        let (ct, ss_encap) = pk.encapsulate(&mut rng);
        // Modify the CT
        let mut modified_bytes = ct.to_bytes();
        modified_bytes[0] ^= 1; // Flip a bit
        let modified_ct = kem768::Ciphertext::from(&modified_bytes);
        let ss_decap = sk.decapsulate(&modified_ct);
        // Should produce different secret
        assert_ne!(ss_encap, ss_decap);
    }

    #[test]
    fn test_ciphertext_size() {
        let mut rng = OsRng;
        let (_, pk) = kem768::generate_keypair(&mut rng);
        let (ct, _) = pk.encapsulate(&mut rng);
        assert_eq!(ct.to_bytes().len(), kem768::CIPHERTEXT_SIZE);
    }
}
