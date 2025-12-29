// tests/cross_crate_tests.rs
use x_wing::{Decapsulate, Encapsulate};

#[ignore]
#[test]
fn cross_check_with_rustcrypto_xwing() {
    // This test is ignored due to rand_core version conflicts between crates
    // TODO: Fix when RustCrypto x-wing stabilizes on rand_core 0.9
}
