use rand_core::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

pub trait DhTrait<const SECRET_SIZE: usize, const PUBLIC_SIZE: usize, const SHARED_SIZE: usize>:
    Send + Sync
{
    type SecretKey: AsRef<[u8]> + Zeroize + Sized;
    type PublicKey: AsRef<[u8]> + Sized;
    type Shared: AsRef<[u8]> + Zeroize + Sized;

    /// Generate a random secret key (unclamped).
    fn generate_secret(rng: &mut impl RngCore) -> Self::SecretKey;

    /// Clamp a raw byte array to a valid secret key (curve-specific).
    fn clamp_secret(bytes: [u8; SECRET_SIZE]) -> Self::SecretKey;

    /// Compute public key from secret key.
    fn public_from_secret(secret: &Self::SecretKey) -> Self::PublicKey;

    /// Perform Diffie-Hellman computation.
    fn diffie_hellman(secret: &Self::SecretKey, public: &Self::PublicKey) -> Self::Shared;

    /// Prepare any input (e.g., shared secret, public key) for combiner by hashing to 32 bytes if needed.
    /// Default impl: Copy if 32 bytes, hash otherwise.
    fn prepare_for_combiner<T: AsRef<[u8]>>(input: &T) -> [u8; 32] {
        let bytes = input.as_ref();
        if bytes.len() == 32 {
            bytes.try_into().expect("Invalid 32-byte length")
        } else {
            Sha3_256::digest(bytes).into()
        }
    }

    /// Generate ephemeral keypair (clamped).
    fn generate_ephemeral(rng: &mut impl RngCore) -> (Self::SecretKey, Self::PublicKey) {
        let mut bytes = [0u8; SECRET_SIZE];
        rng.fill_bytes(&mut bytes);
        let secret = Self::clamp_secret(bytes);
        let public = Self::public_from_secret(&secret);
        (secret, public)
    }

    /// Create secret from fixed bytes (for derandomized modes), clamping it.
    fn secret_from_bytes(bytes: [u8; SECRET_SIZE]) -> Self::SecretKey {
        Self::clamp_secret(bytes)
    }
}
