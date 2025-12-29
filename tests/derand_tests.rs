// tests/derand_tests.rs

use pq_xwing_kem::xwing768::{DecapsulationKey, EncapsulationKey};

#[test]
fn test_derandomized_encapsulation() {
    let seed = [0u8; 32]; // or any fixed seed
    let pk = EncapsulationKey::from_seed(&seed);

    let eseed = [1u8; 64]; // fixed encapsulation seed
    let (ct, ss) = pk.encapsulate_derand(&eseed);

    // You can now assert against known values, or just verify round-trip
    let sk = DecapsulationKey::from_seed(&seed);
    let ss_decap = sk.decapsulate(&ct).unwrap();
    assert_eq!(ss, ss_decap);
}
