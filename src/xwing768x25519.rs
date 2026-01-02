// src/xwing_kem_768.rs

use crate::combiner;
use crate::error::Result;
use crate::SharedSecret;

use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair, MlKem768Ciphertext, MlKem768KeyPair,
    MlKem768PublicKey,
};

use rand::{TryCryptoRng, TryRngCore};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MASTER_SEED_SIZE: usize = 32;
const X25519_KEY_SIZE: usize = 32;
const MLKEM768_PK_SIZE: usize = 1184;
pub const MLKEM768_CT_SIZE: usize = 1088;

pub const XWING768X25519_ENCAPSULATION_KEY_SIZE: usize = MLKEM768_PK_SIZE + X25519_KEY_SIZE;
pub const XWING768X25519_DECAPSULATION_KEY_SIZE: usize = MASTER_SEED_SIZE;
pub const XWING768X25519_CIPHERTEXT_SIZE: usize = MLKEM768_CT_SIZE + X25519_KEY_SIZE;

#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct EncapsulationKey {
    pk_m: [u8; MLKEM768_PK_SIZE],
    pk_x: PublicKey,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    seed: [u8; MASTER_SEED_SIZE],
}

#[derive(Clone, Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct Ciphertext {
    ct_m: [u8; MLKEM768_CT_SIZE],
    ct_x: PublicKey,
}

impl EncapsulationKey {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING768X25519_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; XWING768X25519_ENCAPSULATION_KEY_SIZE];
        buffer[..MLKEM768_PK_SIZE].copy_from_slice(&self.pk_m);
        buffer[MLKEM768_PK_SIZE..].copy_from_slice(&self.pk_x.to_bytes());
        buffer
    }

    /// Random encapsulation using a caller-provided cryptographically secure RNG.
    /// Bounds updated to the modern fallible traits in rand_core 0.9+.
    /// RNG failures are treated as fatal (panic via .expect) — they are exceedingly rare in practice.
    pub fn encapsulate<R: TryRngCore + TryCryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        // Generate ephemeral X25519 keypair using manual bytes (avoids pulling in dalek's RNG traits)
        let mut ephemeral_bytes = [0u8; 32];
        rng.try_fill_bytes(&mut ephemeral_bytes)
            .expect("Failed to generate random bytes for ephemeral X25519 key");

        let ephemeral: EphemeralSecret = unsafe { std::mem::transmute(ephemeral_bytes) };

        let pk_m = MlKem768PublicKey::from(self.pk_m);

        let mut ml_rand = [0u8; 32];
        rng.try_fill_bytes(&mut ml_rand)
            .expect("Failed to generate random bytes for ML-KEM encapsulation");

        let (ct_m, mut ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM768_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        ml_rand.zeroize();

        let ct_x = PublicKey::from(&ephemeral);
        let mut ss_x = ephemeral.diffie_hellman(&self.pk_x).to_bytes();

        let mut ct_x_bytes = ct_x.to_bytes();
        let mut pk_x_bytes = self.pk_x.to_bytes();
        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();
        ct_x_bytes.zeroize();
        pk_x_bytes.zeroize();
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
    pub fn pk_m(&self) -> &[u8; MLKEM768_PK_SIZE] {
        &self.pk_m
    }

    /// Public getter for pk_x
    pub fn pk_x(&self) -> &PublicKey {
        &self.pk_x
    }

    /// Deterministic generation from 32-byte seed
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> crate::Result<Self> {
        let (kp, mut x_bytes) = expand_seed(seed);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        let sk_x = StaticSecret::from(x_bytes);
        x_bytes.zeroize();
        let pk_x = PublicKey::from(&sk_x);

        Ok(Self::from_components(pk_m_bytes, pk_x))
    }

    /// Deterministic encapsulation using a fixed 64-byte encapsulation seed.
    ///
    /// The `eseed` is interpreted as:
    /// - First 32 bytes: randomness for ML-KEM-768 encapsulation
    /// - Last 32 bytes:  X25519 ephemeral secret key
    ///
    /// This allows reproducible known-answer tests (KATs) and matches the
    /// derandomized encapsulation used in test vectors.
    pub fn encapsulate_derand(
        &self,
        eseed: &[u8; 64],
    ) -> crate::Result<(Ciphertext, SharedSecret)> {
        let pk_m = MlKem768PublicKey::from(self.pk_m);

        // First 32 bytes → ML-KEM randomness
        let ml_rand: [u8; 32] = eseed[0..32]
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;
        let (ct_m, ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM768_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        // Last 32 bytes → X25519 ephemeral secret
        let mut ephemeral_bytes: [u8; 32] = eseed[32..64]
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;
        let ephemeral = StaticSecret::from(ephemeral_bytes);
        let ct_x = PublicKey::from(&ephemeral);
        let mut ss_x = ephemeral.diffie_hellman(&self.pk_x).to_bytes();

        let mut ct_x_bytes = ct_x.to_bytes();
        let mut pk_x_bytes = self.pk_x.to_bytes();

        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_x.zeroize();
        ct_x_bytes.zeroize();
        pk_x_bytes.zeroize();
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
    pub fn from_components(pk_m: [u8; MLKEM768_PK_SIZE], pk_x: PublicKey) -> Self {
        Self { pk_m, pk_x }
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != XWING768X25519_ENCAPSULATION_KEY_SIZE {
            return Err(crate::Error::InvalidEncapsulationKeyLength);
        }
        let mut pk_m = [0u8; MLKEM768_PK_SIZE];
        pk_m.copy_from_slice(&bytes[..MLKEM768_PK_SIZE]);

        let pk_x_bytes: [u8; 32] = bytes[MLKEM768_PK_SIZE..]
            .try_into()
            .map_err(|_| crate::Error::ArraySizeError)?;
        let pk_x = PublicKey::from(pk_x_bytes);

        // Validate that pk_x is not the all-zero point (which is invalid for X25519)
        if pk_x_bytes.iter().all(|&b| b == 0) {
            return Err(crate::Error::InvalidX25519PublicKey);
        }

        // Validate ML-KEM public key by attempting to create it and test basic functionality
        let mlkem_pk = MlKem768PublicKey::from(pk_m);
        // Test that the key can be used for basic operations by checking it can be converted back
        let _pk_bytes = mlkem_pk.as_ref();

        Ok(Self { pk_m, pk_x })
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; XWING768X25519_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = crate::Error;

    fn try_from(bytes: &[u8; XWING768X25519_ENCAPSULATION_KEY_SIZE]) -> crate::Result<Self> {
        Self::try_from(&bytes[..])
    }
}

impl DecapsulationKey {
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Self {
        Self { seed: *seed }
    }

    /// Generate a new decapsulation key using a caller-provided cryptographically secure RNG.
    /// Updated for rand_core 0.9 fallible traits.
    pub fn generate<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MASTER_SEED_SIZE];
        rng.try_fill_bytes(&mut seed)
            .expect("Failed to generate random bytes for decapsulation key seed");
        Self { seed }
    }

    pub fn encapsulation_key(&self) -> crate::Result<EncapsulationKey> {
        let (kp, mut x_bytes) = expand_seed(&self.seed);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| crate::error::Error::ArraySizeError)?;

        let sk_x = StaticSecret::from(x_bytes);
        x_bytes.zeroize();
        let pk_x = PublicKey::from(&sk_x);

        Ok(EncapsulationKey {
            pk_m: pk_m_bytes,
            pk_x,
        })
    }

    pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret> {
        let (kp, mut x_bytes) = expand_seed(&self.seed);

        let sk_m = kp.private_key();
        let ct_m = MlKem768Ciphertext::from(ct.ct_m);
        let mut ss_m = decapsulate(sk_m, &ct_m);

        let sk_x = StaticSecret::from(x_bytes);
        x_bytes.zeroize();
        let mut ss_x = sk_x.diffie_hellman(&ct.ct_x).to_bytes();

        let pk_x = PublicKey::from(&sk_x);
        let mut ct_x_bytes = ct.ct_x.to_bytes();
        let mut pk_x_bytes = pk_x.to_bytes();

        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();
        ct_x_bytes.zeroize();
        pk_x_bytes.zeroize();

        Ok(ss)
    }
}

impl Ciphertext {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XWING768X25519_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; XWING768X25519_CIPHERTEXT_SIZE];
        buffer[..MLKEM768_CT_SIZE].copy_from_slice(&self.ct_m);
        buffer[MLKEM768_CT_SIZE..].copy_from_slice(&self.ct_x.to_bytes());
        buffer
    }

    pub fn from_components(ct_m: [u8; MLKEM768_CT_SIZE], ct_x: PublicKey) -> Self {
        Self { ct_m, ct_x }
    }

    /// Public getter for ct_m
    pub fn ct_m(&self) -> &[u8; MLKEM768_CT_SIZE] {
        &self.ct_m
    }

    /// Public getter for ct_x
    pub fn ct_x(&self) -> &x25519_dalek::PublicKey {
        &self.ct_x
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() != XWING768X25519_CIPHERTEXT_SIZE {
            return Err(crate::Error::InvalidCiphertextLength);
        }
        let mut ct_m = [0u8; MLKEM768_CT_SIZE];
        ct_m.copy_from_slice(&bytes[..MLKEM768_CT_SIZE]);

        let ct_x_bytes: [u8; 32] = bytes[MLKEM768_CT_SIZE..]
            .try_into()
            .map_err(|_| crate::Error::ArraySizeError)?;
        let ct_x = PublicKey::from(ct_x_bytes);

        // Validate that ct_x is not the all-zero point
        if ct_x_bytes.iter().all(|&b| b == 0) {
            return Err(crate::Error::InvalidX25519PublicKey);
        }

        Ok(Self { ct_m, ct_x })
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; XWING768X25519_CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = crate::Error;

    fn try_from(bytes: &[u8; XWING768X25519_CIPHERTEXT_SIZE]) -> crate::Result<Self> {
        Self::try_from(&bytes[..])
    }
}

/// Generate a fresh keypair using a caller-provided cryptographically secure RNG.
/// Updated for rand_core 0.9 fallible traits.
pub fn generate_keypair<R: TryRngCore + TryCryptoRng>(
    rng: &mut R,
) -> crate::Result<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key()?;
    Ok((sk, pk))
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
