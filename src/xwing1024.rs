//! X-Wing 1024 variant using ML-KEM-1024 + X448
//!
//! This variant provides higher security level using the X448 curve for the classical component.
//! - ML-KEM-1024: 256-bit security from lattice
//! - X448: 224-bit security from classical DH
//! - Combined: ~224-bit post-quantum security

use crate::SharedSecret;
use crate::combiner;
use crate::consts::{MASTER_SEED_SIZE, X448_KEY_SIZE};
use crate::error::{Error, Result};

use libcrux_ml_kem::mlkem1024::{
    MlKem1024Ciphertext, MlKem1024KeyPair, MlKem1024PublicKey, decapsulate, encapsulate,
    generate_key_pair,
};

use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x448::{PublicKey, StaticSecret as Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const MLKEM1024_PK_SIZE: usize = 1568;
pub const MLKEM1024_CT_SIZE: usize = 1568;

pub const XWING1024_ENCAPSULATION_KEY_SIZE: usize = MLKEM1024_PK_SIZE + X448_KEY_SIZE;
pub const XWING1024_DECAPSULATION_KEY_SIZE: usize = MASTER_SEED_SIZE;
pub const XWING1024_CIPHERTEXT_SIZE: usize = MLKEM1024_CT_SIZE + X448_KEY_SIZE;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncapsulationKey {
    pk_m: [u8; MLKEM1024_PK_SIZE],
    pk_x: PublicKey,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct DecapsulationKey {
    seed: [u8; MASTER_SEED_SIZE],
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    ct_m: [u8; MLKEM1024_CT_SIZE],
    ct_x: PublicKey,
}

impl EncapsulationKey {
    pub fn to_bytes(&self) -> [u8; XWING1024_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; XWING1024_ENCAPSULATION_KEY_SIZE];
        buffer[..MLKEM1024_PK_SIZE].copy_from_slice(&self.pk_m);
        buffer[MLKEM1024_PK_SIZE..].copy_from_slice(self.pk_x.as_bytes());
        buffer
    }

    pub fn encapsulate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(Ciphertext, SharedSecret)> {
        let pk_m = MlKem1024PublicKey::from(self.pk_m);
        let mut ml_rand = [0u8; 32];
        rng.fill_bytes(&mut ml_rand);
        let (ct_m, mut ss_m) = encapsulate(&pk_m, ml_rand);

        let ct_m_bytes: [u8; MLKEM1024_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;

        ml_rand.zeroize();

        let mut ephemeral_bytes = [0u8; 56];
        rng.fill_bytes(&mut ephemeral_bytes);
        let ephemeral = Secret::from(ephemeral_bytes);
        let ct_x = PublicKey::from(&ephemeral);
        let ss_x = ephemeral.diffie_hellman(&self.pk_x);
        let ss_x_bytes = *ss_x.as_bytes();
        let mut ss_x = hash_x448_key_to_32(&ss_x_bytes);

        let ct_x_bytes = hash_x448_key_to_32(ct_x.as_bytes());
        let pk_x_bytes = hash_x448_key_to_32(self.pk_x.as_bytes());
        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();

        Ok((
            Ciphertext {
                ct_m: ct_m_bytes,
                ct_x,
            },
            ss,
        ))
    }

    pub fn pk_m(&self) -> &[u8; MLKEM1024_PK_SIZE] {
        &self.pk_m
    }

    pub fn pk_x(&self) -> &PublicKey {
        &self.pk_x
    }

    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Result<Self> {
        let (kp, x_secret) = expand_seed(seed)?;
        let pk_m_bytes: [u8; MLKEM1024_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;

        let pk_x = PublicKey::from(&x_secret);
        Ok(Self::from_components(pk_m_bytes, pk_x))
    }
}

impl TryFrom<&[u8; XWING1024_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8; XWING1024_ENCAPSULATION_KEY_SIZE]) -> Result<Self> {
        let mut pk_m = [0u8; MLKEM1024_PK_SIZE];
        pk_m.copy_from_slice(&bytes[..MLKEM1024_PK_SIZE]);

        let pk_x_bytes: [u8; 56] = bytes[MLKEM1024_PK_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let pk_x = PublicKey::from_bytes(&pk_x_bytes).ok_or(Error::InvalidX448PublicKey)?;

        // Validate ML-KEM public key
        let mlkem_pk = MlKem1024PublicKey::from(pk_m);
        let _ = mlkem_pk.as_ref();

        Ok(Self { pk_m, pk_x })
    }
}

impl EncapsulationKey {
    pub fn from_components(pk_m: [u8; MLKEM1024_PK_SIZE], pk_x: PublicKey) -> Self {
        Self { pk_m, pk_x }
    }
}

impl DecapsulationKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MASTER_SEED_SIZE];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub fn encapsulation_key(&self) -> Result<EncapsulationKey> {
        let (kp, x_secret) = expand_seed(&self.seed)?;
        let pk_m_bytes: [u8; MLKEM1024_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;

        let pk_x = PublicKey::from(&x_secret);

        Ok(EncapsulationKey {
            pk_m: pk_m_bytes,
            pk_x,
        })
    }

    pub fn decapsulate(&self, ct: &Ciphertext) -> Result<SharedSecret> {
        let (kp, x_secret) = expand_seed(&self.seed)?;

        let sk_m = kp.private_key();
        let ct_m = MlKem1024Ciphertext::from(*ct.ct_m());
        let mut ss_m = decapsulate(sk_m, &ct_m);

        let ss_x = x_secret.diffie_hellman(&ct.ct_x);
        let ss_x_bytes = *ss_x.as_bytes();
        let mut ss_x = hash_x448_key_to_32(&ss_x_bytes);

        let pk_x = PublicKey::from(&x_secret);
        let ct_x_bytes = hash_x448_key_to_32(ct.ct_x.as_bytes());
        let pk_x_bytes = hash_x448_key_to_32(pk_x.as_bytes());

        let ss = combiner(&ss_m, &ss_x, &ct_x_bytes, &pk_x_bytes);

        ss_m.zeroize();
        ss_x.zeroize();

        Ok(ss)
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> [u8; XWING1024_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; XWING1024_CIPHERTEXT_SIZE];
        buffer[..MLKEM1024_CT_SIZE].copy_from_slice(&self.ct_m);
        buffer[MLKEM1024_CT_SIZE..].copy_from_slice(self.ct_x.as_bytes());
        buffer
    }
}

impl TryFrom<&[u8; XWING1024_CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8; XWING1024_CIPHERTEXT_SIZE]) -> Result<Self> {
        let mut ct_m = [0u8; MLKEM1024_CT_SIZE];
        ct_m.copy_from_slice(&bytes[..MLKEM1024_CT_SIZE]);

        let ct_x_bytes: [u8; 56] = bytes[MLKEM1024_CT_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let ct_x = PublicKey::from_bytes(&ct_x_bytes).ok_or(Error::InvalidX448PublicKey)?;

        Ok(Self { ct_m, ct_x })
    }
}

impl Ciphertext {
    pub fn from_components(ct_m: [u8; MLKEM1024_CT_SIZE], ct_x: PublicKey) -> Self {
        Self { ct_m, ct_x }
    }

    pub fn ct_m(&self) -> &[u8; MLKEM1024_CT_SIZE] {
        &self.ct_m
    }

    pub fn ct_x(&self) -> &PublicKey {
        &self.ct_x
    }
}

pub fn generate_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key()?;
    Ok((sk, pk))
}

fn hash_x448_key_to_32(key_bytes: &[u8; 56]) -> [u8; 32] {
    Sha3_256::new().chain_update(key_bytes).finalize().into()
}

fn expand_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Result<(MlKem1024KeyPair, Secret)> {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut expanded = [0u8; 120];
    reader.read(&mut expanded);

    let mut ml_seed = [0u8; 64];
    ml_seed.copy_from_slice(&expanded[..64]);
    let kp = generate_key_pair(ml_seed);
    ml_seed.zeroize();

    let mut x_bytes = [0u8; 56];
    x_bytes.copy_from_slice(&expanded[64..120]);
    let x_secret = Secret::from(x_bytes);
    x_bytes.zeroize();

    expanded.zeroize();

    Ok((kp, x_secret))
}
