// src/xwing_kem_768.rs

use crate::combiner;
use crate::consts::{MASTER_SEED_SIZE, X25519_KEY_SIZE};
use crate::SharedSecret;

use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair, MlKem768Ciphertext, MlKem768KeyPair,
    MlKem768PublicKey,
};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MLKEM768_PK_SIZE: usize = 1184;
pub const MLKEM768_CT_SIZE: usize = 1088;

pub const XWING768_ENCAPSULATION_KEY_SIZE: usize = MLKEM768_PK_SIZE + X25519_KEY_SIZE;
pub const XWING768_DECAPSULATION_KEY_SIZE: usize = X25519_KEY_SIZE;
pub const XWING768_CIPHERTEXT_SIZE: usize = MLKEM768_CT_SIZE + X25519_KEY_SIZE;

#[derive(Clone, Debug, PartialEq)]
pub struct EncapsulationKey {
    pk_m: [u8; MLKEM768_PK_SIZE],
    pk_x: PublicKey,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    seed: [u8; MASTER_SEED_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    ct_m: [u8; MLKEM768_CT_SIZE],
    ct_x: PublicKey,
}

impl EncapsulationKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING768_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; XWING768_ENCAPSULATION_KEY_SIZE];
        buffer[..MLKEM768_PK_SIZE].copy_from_slice(&self.pk_m);
        buffer[MLKEM768_PK_SIZE..].copy_from_slice(&self.pk_x.to_bytes());
        buffer
    }

    pub fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> (Ciphertext, SharedSecret) {
        let pk_m = MlKem768PublicKey::from(self.pk_m);
        let mut ml_rand = [0u8; 32];
        rng.fill_bytes(&mut ml_rand);
        let (ct_m, mut ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM768_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .expect("ML-KEM ciphertext size mismatch");

        ml_rand.zeroize();

        let ephemeral = EphemeralSecret::random_from_rng(rng);
        let ct_x = PublicKey::from(&ephemeral);
        let mut ss_x = ephemeral.diffie_hellman(&self.pk_x).to_bytes();

        let ct_x_bytes = ct_x.to_bytes();
        let pk_x_bytes = self.pk_x.to_bytes();
        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();

        (
            Ciphertext {
                ct_m: ct_m_bytes,
                ct_x,
            },
            ss,
        )
    }
}

impl From<&[u8; XWING768_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    fn from(bytes: &[u8; XWING768_ENCAPSULATION_KEY_SIZE]) -> Self {
        let mut pk_m = [0u8; MLKEM768_PK_SIZE];
        pk_m.copy_from_slice(&bytes[..MLKEM768_PK_SIZE]);
        let pk_x_bytes: [u8; 32] = bytes[MLKEM768_PK_SIZE..].try_into().unwrap();
        let pk_x = PublicKey::from(pk_x_bytes);
        Self { pk_m, pk_x }
    }
}

impl DecapsulationKey {
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MASTER_SEED_SIZE];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    #[must_use]
    pub fn encapsulation_key(&self) -> EncapsulationKey {
        let (kp, x_bytes) = expand_seed(&self.seed);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .expect("ML-KEM public key size mismatch");

        let sk_x = StaticSecret::from(x_bytes);
        let pk_x = PublicKey::from(&sk_x);

        EncapsulationKey {
            pk_m: pk_m_bytes,
            pk_x,
        }
    }

    #[must_use]
    pub fn decapsulate(&self, ct: &Ciphertext) -> SharedSecret {
        let (kp, x_bytes) = expand_seed(&self.seed);

        // kp.private_key() returns &MlKem768PrivateKey
        let sk_m = kp.private_key();
        let ct_m = MlKem768Ciphertext::from(ct.ct_m);
        // No extra & on sk_m – it's already a reference
        let mut ss_m = decapsulate(sk_m, &ct_m);

        let sk_x = StaticSecret::from(x_bytes);
        let mut ss_x = sk_x.diffie_hellman(&ct.ct_x).to_bytes();

        let pk_x = PublicKey::from(&sk_x);
        let ct_x_bytes = ct.ct_x.to_bytes();
        let pk_x_bytes = pk_x.to_bytes();

        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();

        ss
    }
}
impl Ciphertext {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING768_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; XWING768_CIPHERTEXT_SIZE];
        buffer[..MLKEM768_CT_SIZE].copy_from_slice(&self.ct_m);
        buffer[MLKEM768_CT_SIZE..].copy_from_slice(&self.ct_x.to_bytes());
        buffer
    }
}

impl From<&[u8; XWING768_CIPHERTEXT_SIZE]> for Ciphertext {
    fn from(bytes: &[u8; XWING768_CIPHERTEXT_SIZE]) -> Self {
        let mut ct_m = [0u8; MLKEM768_CT_SIZE];
        ct_m.copy_from_slice(&bytes[..MLKEM768_CT_SIZE]);
        let ct_x_bytes: [u8; 32] = bytes[MLKEM768_CT_SIZE..].try_into().unwrap();
        let ct_x = PublicKey::from(ct_x_bytes);
        Self { ct_m, ct_x }
    }
}

pub fn generate_keypair<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> (DecapsulationKey, EncapsulationKey) {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key();
    (sk, pk)
}

fn expand_seed(seed: &[u8; MASTER_SEED_SIZE]) -> (MlKem768KeyPair, [u8; 32]) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Draft-09: expand to 96 bytes using SHAKE256(sk, 96*8)
    let mut expanded = [0u8; 96];
    reader.read(&mut expanded);

    // Draft-09: ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
    // libcrux expects concatenated d || z, so we provide the first 64 bytes
    let mut ml_seed = [0u8; 64];
    ml_seed.copy_from_slice(&expanded[..64]);
    let kp = generate_key_pair(ml_seed);
    ml_seed.zeroize();

    // Draft-09: sk_X = expanded[64:96]
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&expanded[64..]);

    expanded.zeroize();

    (kp, x_bytes)
}
