//! Unit tests for combiner.

use pq_xwing_kem::combiner::combiner;
use pq_xwing_kem::SHARED_SECRET_SIZE;
use sha3::{Digest, Sha3_256};

#[test]
fn test_combiner_consistency() {
    let ss_m = [1u8; 32];
    let ss_x = [2u8; 32];
    let ct_x = [3u8; 32];
    let pk_x = [4u8; 32];

    let result1 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
    let result2 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

    assert_eq!(result1, result2);
    assert_eq!(result1.len(), SHARED_SECRET_SIZE);
}

#[test]
fn test_combiner_different_inputs() {
    let ss_m = [1u8; 32];
    let ss_x = [2u8; 32];
    let ct_x = [3u8; 32];
    let pk_x = [4u8; 32];

    let result1 = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
    let result2 = combiner(&ss_x, &ss_m, &pk_x, &ct_x); // swapped

    assert_ne!(result1, result2);
}

#[test]
fn test_combiner_includes_label() {
    // The label should ensure output differs from plain SHA3-256 of inputs
    let ss_m = [0u8; 32];
    let ss_x = [0u8; 32];
    let ct_x = [0u8; 32];
    let pk_x = [0u8; 32];

    let plain_hash = Sha3_256::new()
        .chain_update(ss_m)
        .chain_update(ss_x)
        .chain_update(ct_x)
        .chain_update(pk_x)
        .finalize();
    let combined = combiner(&ss_m, &ss_x, &ct_x, &pk_x);

    assert_ne!(plain_hash.as_slice(), combined.as_slice());
}

#[test]
fn test_combiner_all_zero_inputs() {
    let ss_m = [0u8; 32];
    let ss_x = [0u8; 32];
    let ct_x = [0u8; 32];
    let pk_x = [0u8; 32];
    let result = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
    // Should still produce a non-zero hash due to the label
    assert!(!result.iter().all(|&b| b == 0));
    assert_eq!(result.len(), SHARED_SECRET_SIZE);
}
