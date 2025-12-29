// tests/determinism_tests.rs
use pq_xwing_kem::xwing768::{DecapsulationKey, EncapsulationKey};

const FIXED_SEED: [u8; 32] = [0x42; 32];
const FIXED_ESEED: [u8; 64] = [0x99; 64];

// Real values from your implementation (all-zero seed → deterministic output)
const EXPECTED_PK_FIRST_32: [u8; 32] = [
    96, 186, 206, 95, 68, 141, 117, 152, 50, 14, 21, 164, 135, 90, 130, 172, 120, 140, 97, 136,
    101, 149, 210, 4, 56, 161, 129, 141, 82, 20, 157, 229,
];

// Optional: fill these after printing from test_full_deterministic_flow
// const EXPECTED_CT_FIRST_32: [u8; 32] = [...];
// const EXPECTED_SS: [u8; 32] = [...];

#[test]
fn test_deterministic_key_generation() {
    let pk1 = EncapsulationKey::from_seed(&FIXED_SEED);
    let pk2 = EncapsulationKey::from_seed(&FIXED_SEED);

    assert_eq!(pk1.to_bytes().as_slice(), pk2.to_bytes().as_slice());
    assert_eq!(&pk1.to_bytes()[..32], EXPECTED_PK_FIRST_32);
}

#[test]
fn test_full_deterministic_flow() {
    let pk = EncapsulationKey::from_seed(&FIXED_SEED);
    let sk = DecapsulationKey::from_seed(&FIXED_SEED);

    let (ct1, ss1) = pk.encapsulate_derand(&FIXED_ESEED);
    let (ct2, ss2) = pk.encapsulate_derand(&FIXED_ESEED);

    assert_eq!(ct1.to_bytes().as_slice(), ct2.to_bytes().as_slice());
    assert_eq!(ss1, ss2);

    // Optional strong regression checks — uncomment and fill once you capture values
    // assert_eq!(&ct1.to_bytes()[..32], EXPECTED_CT_FIRST_32);
    // assert_eq!(ss1, EXPECTED_SS);

    let ss_decap = sk.decapsulate(&ct1).unwrap();
    assert_eq!(ss1, ss_decap);
}
