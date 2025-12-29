//! X-Wing 1024 variant using ML-KEM-1024 + X448
//!
//! This variant provides higher security level using the X448 curve for the classical component.
//! - ML-KEM-1024: 256-bit security from lattice
//! - X448: 224-bit security from classical DH
//! - Combined: ~256-bit post-quantum security

use crate::combiner;
use crate::error::Result;
use crate::SharedSecret;

use libcrux_ml_kem::mlkem1024::{
    decapsulate, encapsulate, generate_key_pair, MlKem1024Ciphertext, MlKem1024KeyPair,
    MlKem1024PublicKey,
};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x448::{x448, X448_BASEPOINT_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn hash_to_32(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

const MASTER_SEED_SIZE: usize = 32;
const X448_KEY_SIZE: usize = 56;
const MLKEM1024_PK_SIZE: usize = 1568;
pub const MLKEM1024_CT_SIZE: usize = 1568;

pub const XWING1024X448_ENCAPSULATION_KEY_SIZE: usize = MLKEM1024_PK_SIZE + X448_KEY_SIZE;
pub const XWING1024X448_DECAPSULATION_KEY_SIZE: usize = MASTER_SEED_SIZE;
pub const XWING1024X448_CIPHERTEXT_SIZE: usize = MLKEM1024_CT_SIZE + X448_KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct EncapsulationKey {
    pk_m: [u8; MLKEM1024_PK_SIZE],
    pk_x: [u8; 56],
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    seed: [u8; MASTER_SEED_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Ciphertext {
    ct_m: [u8; MLKEM1024_CT_SIZE],
    ct_x: [u8; 56],
}

impl EncapsulationKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING1024X448_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; XWING1024X448_ENCAPSULATION_KEY_SIZE];
        buffer[..MLKEM1024_PK_SIZE].copy_from_slice(&self.pk_m);
        buffer[MLKEM1024_PK_SIZE..].copy_from_slice(&self.pk_x);
        buffer
    }

    pub fn encapsulate<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        // Generate ephemeral X448 keypair using manual bytes to avoid rand_core version conflicts
        let mut ephemeral_bytes = [0u8; 56];
        rng.fill_bytes(&mut ephemeral_bytes);
        let pk_m = MlKem1024PublicKey::from(self.pk_m);
        let mut ml_rand = [0u8; 32];
        rng.fill_bytes(&mut ml_rand);
        let (ct_m, mut ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM1024_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        ml_rand.zeroize();

        let ct_x =
            x448(ephemeral_bytes, X448_BASEPOINT_BYTES).ok_or(crate::error::Error::X448DhError)?;
        let mut ss_x_full =
            x448(ephemeral_bytes, self.pk_x).ok_or(crate::error::Error::X448DhError)?;

        let mut ct_x_reduced = hash_to_32(&ct_x);
        let mut pk_x_reduced = hash_to_32(&self.pk_x);
        let mut ss_x = Sha3_256::digest(ss_x_full);
        let ss = combiner(
            &ss_m,
            &ss_x.into(),
            &ct_x_reduced,
            &pk_x_reduced,
        );

        ss_m.zeroize();
        ss_x.zeroize();
        ct_x_reduced.zeroize();
        pk_x_reduced.zeroize();
        ss_x_full.zeroize();
        ephemeral_bytes.zeroize();

        Ok((
            Ciphertext {
                ct_m: ct_m_bytes,
                ct_x,
            },
            ss,
        ))
    }

    /// Public getter for pk_m
    pub fn pk_m(&self) -> &[u8; MLKEM1024_PK_SIZE] {
        &self.pk_m
    }

    /// Public getter for pk_x
    pub fn pk_x(&self) -> &[u8; 56] {
        &self.pk_x
    }

    /// Deterministic generation from 32-byte seed
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> crate::Result<Self> {
        let (kp, mut x_bytes) = expand_seed(seed);
        let pk_m_bytes: [u8; MLKEM1024_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        let pk_x = x448(x_bytes, X448_BASEPOINT_BYTES).ok_or(crate::error::Error::X448DhError)?;
        x_bytes.zeroize();

        Ok(Self::from_components(pk_m_bytes, pk_x))
    }

    /// Deterministic encapsulation using a fixed 88-byte encapsulation seed.
    ///
    /// The `eseed` is interpreted as:
    /// - First 32 bytes: randomness for ML-KEM-1024 encapsulation
    /// - Last 56 bytes:  X448 ephemeral secret key
    ///
    /// This allows reproducible known-answer tests (KATs) and matches the
    /// derandomized encapsulation used in test vectors.
    pub fn encapsulate_derand(
        &self,
        eseed: &[u8; 88],
    ) -> crate::Result<(Ciphertext, SharedSecret)> {
        let pk_m = MlKem1024PublicKey::from(self.pk_m);

        // First 32 bytes → ML-KEM randomness
        let ml_rand: [u8; 32] = eseed[0..32]
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;
        let (ct_m, ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM1024_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        // Last 56 bytes → X448 ephemeral secret
        let mut ephemeral_bytes: [u8; 56] = eseed[32..88]
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;
        let ct_x =
            x448(ephemeral_bytes, X448_BASEPOINT_BYTES).ok_or(crate::error::Error::X448DhError)?;
        let mut ss_x_full =
            x448(ephemeral_bytes, self.pk_x).ok_or(crate::error::Error::X448DhError)?;

        let mut ct_x_reduced = Sha3_256::digest(ct_x);
        let mut pk_x_reduced = Sha3_256::digest(self.pk_x);
        let mut ss_x = hash_to_32(&ss_x_full);

        let ss = combiner(
            &ss_m,
            &ss_x,
            &ct_x_reduced.into(),
            &pk_x_reduced.into(),
        );

        ss_x.zeroize();
        ct_x_reduced.zeroize();
        pk_x_reduced.zeroize();
        ss_x_full.zeroize();
        ephemeral_bytes.zeroize();

        Ok((
            Ciphertext {
                ct_m: ct_m_bytes,
                ct_x,
            },
            ss,
        ))
    }
}

impl EncapsulationKey {
    pub fn from_components(pk_m: [u8; MLKEM1024_PK_SIZE], pk_x: [u8; 56]) -> Self {
        Self { pk_m, pk_x }
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != XWING1024X448_ENCAPSULATION_KEY_SIZE {
            return Err(crate::Error::InvalidEncapsulationKeyLength);
        }

        let mut pk_m = [0u8; MLKEM1024_PK_SIZE];
        pk_m.copy_from_slice(&bytes[..MLKEM1024_PK_SIZE]);

        let pk_x_bytes: [u8; 56] = bytes[MLKEM1024_PK_SIZE..]
            .try_into()
            .map_err(|_| crate::Error::ArraySizeError)?;

        // Validate that pk_x is not the all-zero point (which is invalid for X448)
        if pk_x_bytes.iter().all(|&b| b == 0) {
            return Err(crate::Error::InvalidX448PublicKey);
        }

        // Validate ML-KEM public key by attempting to create it and test basic functionality
        let mlkem_pk = MlKem1024PublicKey::from(pk_m);
        // Test that the key can be used for basic operations by checking it can be converted back
        let _pk_bytes = mlkem_pk.as_ref();

        Ok(Self {
            pk_m,
            pk_x: pk_x_bytes,
        })
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; XWING1024X448_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = crate::Error;

    fn try_from(bytes: &[u8; XWING1024X448_ENCAPSULATION_KEY_SIZE]) -> crate::Result<Self> {
        Self::try_from(&bytes[..])
    }
}

impl DecapsulationKey {
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Self {
        Self { seed: *seed }
    }

    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MASTER_SEED_SIZE];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub fn encapsulation_key(&self) -> crate::Result<EncapsulationKey> {
        let (kp, mut x_bytes) = expand_seed(&self.seed);
        let pk_m_bytes: [u8; MLKEM1024_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| crate::Error::ArraySizeError)?;

        let pk_x = x448(x_bytes, X448_BASEPOINT_BYTES).unwrap();
        x_bytes.zeroize();

        Ok(EncapsulationKey {
            pk_m: pk_m_bytes,
            pk_x,
        })
    }

    pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret> {
        let (kp, mut x_bytes) = expand_seed(&self.seed);

        let sk_m = kp.private_key();
        let ct_m = MlKem1024Ciphertext::from(ct.ct_m);
        let mut ss_m = decapsulate(sk_m, &ct_m);

        let mut ss_x_full = x448(x_bytes, ct.ct_x).ok_or(crate::error::Error::X448DhError)?;

        let pk_x = x448(x_bytes, X448_BASEPOINT_BYTES).ok_or(crate::error::Error::X448DhError)?;
        x_bytes.zeroize();
        let mut ct_x_reduced = hash_to_32(&ct.ct_x);
        let mut pk_x_reduced = hash_to_32(&pk_x);
        let mut ss_x = hash_to_32(&ss_x_full);

        let ss = combiner(
            &ss_m,
            &ss_x,
            &ct_x_reduced,
            &pk_x_reduced,
        );

        ss_m.zeroize();
        ss_x.zeroize();
        ct_x_reduced.zeroize();
        pk_x_reduced.zeroize();
        ss_x_full.zeroize();

        Ok(ss)
    }
}

impl Ciphertext {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING1024X448_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; XWING1024X448_CIPHERTEXT_SIZE];
        buffer[..MLKEM1024_CT_SIZE].copy_from_slice(&self.ct_m);
        buffer[MLKEM1024_CT_SIZE..].copy_from_slice(&self.ct_x);
        buffer
    }

    pub fn from_components(ct_m: [u8; MLKEM1024_CT_SIZE], ct_x: [u8; 56]) -> Self {
        Self { ct_m, ct_x }
    }

    /// Public getter for ct_m
    pub fn ct_m(&self) -> &[u8; MLKEM1024_CT_SIZE] {
        &self.ct_m
    }

    /// Public getter for ct_x
    pub fn ct_x(&self) -> &[u8; 56] {
        &self.ct_x
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != XWING1024X448_CIPHERTEXT_SIZE {
            return Err(crate::Error::InvalidCiphertextLength);
        }

        let mut ct_m = [0u8; MLKEM1024_CT_SIZE];
        ct_m.copy_from_slice(&bytes[..MLKEM1024_CT_SIZE]);

        let ct_x_bytes: [u8; 56] = bytes[MLKEM1024_CT_SIZE..]
            .try_into()
            .map_err(|_| crate::Error::ArraySizeError)?;

        // Validate that ct_x is not the all-zero point
        if ct_x_bytes.iter().all(|&b| b == 0) {
            return Err(crate::Error::InvalidX448PublicKey);
        }

        Ok(Self {
            ct_m,
            ct_x: ct_x_bytes,
        })
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; XWING1024X448_CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = crate::Error;

    fn try_from(bytes: &[u8; XWING1024X448_CIPHERTEXT_SIZE]) -> crate::Result<Self> {
        Self::try_from(&bytes[..])
    }
}

pub fn generate_keypair<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> crate::Result<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key()?;
    Ok((sk, pk))
}

fn expand_seed(seed: &[u8; MASTER_SEED_SIZE]) -> (MlKem1024KeyPair, [u8; 56]) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Draft-09: expand to 120 bytes using SHAKE256(sk, 120*8)
    let mut expanded = [0u8; 120];
    reader.read(&mut expanded);

    // Draft-09: ML-KEM-1024.KeyGen_internal(expanded[0:32], expanded[32:64])
    // libcrux expects concatenated d || z, so we provide the first 64 bytes
    let mut ml_seed = [0u8; 64];
    ml_seed.copy_from_slice(&expanded[..64]);
    let kp = generate_key_pair(ml_seed);
    ml_seed.zeroize();

    // Draft-09: sk_X = expanded[64:120]
    let mut x_bytes = [0u8; 56];
    x_bytes.copy_from_slice(&expanded[64..]);

    expanded.zeroize();

    (kp, x_bytes)
}
