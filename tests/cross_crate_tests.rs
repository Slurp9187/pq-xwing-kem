// tests/cross_crate_tests.rs
use pq_xwing_kem::xwing768x25519::EncapsulationKey as MyPK;
use rand_core::{impls, CryptoRng, RngCore};
use x_wing::{Decapsulate, Encapsulate};

#[test]
fn cross_check_with_rustcrypto_xwing() {
    struct SeedRng<'a> {
        data: &'a [u8],
    }

    impl<'a> RngCore for SeedRng<'a> {
        fn next_u32(&mut self) -> u32 {
            impls::next_u32_via_fill(self)
        }

        fn next_u64(&mut self) -> u64 {
            impls::next_u64_via_fill(self)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            if self.data.len() < dest.len() {
                panic!(
                    "SeedRng exhausted: requested {} bytes but only {} remain",
                    dest.len(),
                    self.data.len()
                );
            }
            dest.copy_from_slice(&self.data[..dest.len()]);
            self.data = &self.data[dest.len()..];
        }
    }

    impl<'a> CryptoRng for SeedRng<'a> {}

    let seed = [0x42u8; 32];
    let eseed = [0x99u8; 64];

    let my_pk = MyPK::from_seed(&seed);
    let (my_ct, my_ss) = my_pk.encapsulate_derand(&eseed);

    let mut key_rng = SeedRng { data: &seed };
    let (rc_sk, rc_pk) = x_wing::generate_key_pair(&mut key_rng);

    let mut encaps_rng = SeedRng { data: &eseed };
    let (rc_ct, rc_ss) = rc_pk.encapsulate(&mut encaps_rng).unwrap();

    assert_eq!(my_pk.to_bytes().as_slice(), rc_pk.to_bytes().as_slice());
    assert_eq!(my_ct.to_bytes().as_slice(), rc_ct.to_bytes().as_slice());
    assert_eq!(my_ss, rc_ss);

    let rc_ss_decap = rc_sk.decapsulate(&rc_ct).unwrap();
    assert_eq!(rc_ss, rc_ss_decap);
}
