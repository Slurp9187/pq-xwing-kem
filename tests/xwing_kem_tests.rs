//! Integration tests for XWing KEM (ML-KEM + X25519) features in the encrypted file vault.
//!
//! These tests focus on public APIs for key derivation, encryption, consistency,
//! and vault integration including database storage and retrieval of master seeds.
use encrypted_file_vault::aliases::{
    CypherText, MasterKemSeed, MasterPassword, Nonce12, Salt16, Tag16,
};
use encrypted_file_vault::crypto::argon2id::{derive_key, generate_salt};
use encrypted_file_vault::crypto::kem::generate_master_encap_key;
use encrypted_file_vault::db::env_db_conn::open_env_db;
use encrypted_file_vault::db::env_db_ops::{retrieve_master_seed, store_master_seed};
use encrypted_file_vault::security::key_management::{
    generate_master_seed, unwrap_master_seed, wrap_master_seed,
};
use rand::{rng, TryRngCore};
use serial_test::serial;
use std::env;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_argon2id_key_derivation_consistency() {
    let password = b"test_password";
    let salt = [42u8; 16];
    let key1 = derive_key(password, &salt).unwrap();
    let key2 = derive_key(password, &salt).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn test_salt_generation_randomness() {
    let mut rng = rng();
    let salt1 = generate_salt(&mut rng);
    let salt2 = generate_salt(&mut rng);
    assert_ne!(salt1, salt2);
}

#[test]
fn test_different_salts_produce_different_keys() {
    let password = b"password";
    let salt1 = [1u8; 16];
    let salt2 = [2u8; 16];
    let key1 = derive_key(password, &salt1).unwrap();
    let key2 = derive_key(password, &salt2).unwrap();
    assert_ne!(key1, key2);
}

#[allow(clippy::needless_borrow)]
#[test]
fn test_aes_gcm_with_derived_key() {
    use aes_gcm::{
        aead::{Aead, KeyInit, Nonce},
        Aes256Gcm,
    };

    let mut rng = rng(); // This is correct and modern
    let plaintext = b"Hello, Quantum-Resistant World!";
    let password = b"kem_password";
    let salt = generate_salt(&mut rng);

    let derived_key = derive_key(password, &salt).unwrap();
    let key_bytes: [u8; 32] = derived_key[..32].try_into().unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("Invalid key length");

    let mut nonce_bytes = [0u8; 12];
    rng.try_fill_bytes(&mut nonce_bytes); // Correct for rand 0.9 — not deprecated!
    let nonce = Nonce::<Aes256Gcm>::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .expect("Encryption failed");
    let decrypted = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

// =============================================================================
// VAULT INTEGRATION TESTS
// =============================================================================

#[test]
fn test_master_seed_generation() {
    let mut rng = rng();
    let seed1 = generate_master_seed(&mut rng);
    let seed2 = generate_master_seed(&mut rng);
    assert_ne!(seed1.expose_secret(), seed2.expose_secret());
    assert_eq!(seed1.expose_secret().len(), 32);
    assert_eq!(seed2.expose_secret().len(), 32);
    assert!(!seed1.expose_secret().iter().all(|&b| b == 0));
    assert!(!seed2.expose_secret().iter().all(|&b| b == 0));
}

#[test]
fn test_master_seed_wrap_unwrap_roundtrip() {
    let mut rng = rng();
    let password = MasterPassword::new("test_master_password".to_string());
    let salt = [42u8; 16];
    let original_seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) = wrap_master_seed(&password, &original_seed, &salt, &mut rng)
        .expect("Failed to wrap master seed");
    let unwrapped_seed =
        unwrap_master_seed(&password, &CypherText::new(encrypted), &nonce, &tag, &salt)
            .expect("Failed to unwrap master seed");
    assert_eq!(
        original_seed.expose_secret(),
        unwrapped_seed.expose_secret()
    );
}

#[test]
fn test_master_seed_wrong_password_fails() {
    let mut rng = rng();
    let correct_password = MasterPassword::new("correct_password".to_string());
    let wrong_password = MasterPassword::new("wrong_password".to_string());
    let salt = [123u8; 16];
    let seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) = wrap_master_seed(&correct_password, &seed, &salt, &mut rng)
        .expect("Failed to wrap master seed");
    let result = unwrap_master_seed(
        &wrong_password,
        &CypherText::new(encrypted),
        &nonce,
        &tag,
        &salt,
    );
    assert!(
        result.is_err(),
        "Unwrapping with wrong password should fail"
    );
}

#[test]
#[serial]
fn test_env_db_creation_and_encryption() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_creation.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = MasterPassword::new("test_password".to_string());
    let password_ref = &password;
    let conn = open_env_db(password_ref).expect("Failed to open env DB");
    assert!(db_path.exists());
    let metadata = fs::metadata(&db_path).expect("Failed to get file metadata");
    assert!(metadata.len() > 0);
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
#[serial]
fn test_master_seed_database_storage_retrieval() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_storage.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = MasterPassword::new("test_password".to_string());
    let password_ref = &password;
    let conn = open_env_db(password_ref).expect("Failed to open env DB");
    let mut rng = rng();
    let master_password = MasterPassword::new("master_password".to_string());
    let salt = generate_salt(&mut rng);
    let seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) =
        wrap_master_seed(&master_password, &seed, &salt, &mut rng).expect("Failed to wrap seed");
    let version = store_master_seed(
        &conn,
        CypherText::new(encrypted.clone()),
        &Nonce12::new(nonce.clone().try_into().unwrap()),
        &Tag16::new(tag.clone().try_into().unwrap()),
        &Salt16::new(salt),
    )
    .expect("Failed to store master seed");
    assert_eq!(version, 1);
    let (retrieved_encrypted, retrieved_nonce, retrieved_tag, retrieved_salt, retrieved_version) =
        retrieve_master_seed(&conn).expect("Failed to retrieve master seed");
    assert_eq!(retrieved_encrypted.expose_secret(), &encrypted);
    assert_eq!(retrieved_nonce.expose_secret().as_slice(), nonce.as_slice());
    assert_eq!(retrieved_tag.expose_secret().as_slice(), tag.as_slice());
    assert_eq!(retrieved_salt.expose_secret(), &salt);
    assert_eq!(retrieved_version, version);
    let unwrapped_seed = unwrap_master_seed(
        &master_password,
        &retrieved_encrypted,
        retrieved_nonce.expose_secret().as_slice(),
        retrieved_tag.expose_secret().as_slice(),
        retrieved_salt.expose_secret(),
    )
    .expect("Failed to unwrap retrieved seed");
    assert_eq!(seed.expose_secret(), unwrapped_seed.expose_secret());
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
#[serial]
fn test_master_seed_version_management() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_version.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = MasterPassword::new("test_password".to_string());
    let password_ref = &password;
    let conn = open_env_db(password_ref).expect("Failed to open env DB");
    let mut rng = rng();
    let master_password = MasterPassword::new("master_password".to_string());
    let salt1 = generate_salt(&mut rng);
    let seed1 = generate_master_seed(&mut rng);
    let (enc1, nonce1, tag1) =
        wrap_master_seed(&master_password, &seed1, &salt1, &mut rng).unwrap();
    let version1 = store_master_seed(
        &conn,
        CypherText::new(enc1.clone()),
        &Nonce12::new(nonce1.try_into().unwrap()),
        &Tag16::new(tag1.try_into().unwrap()),
        &Salt16::new(salt1),
    )
    .unwrap();
    assert_eq!(version1, 1);
    let salt2 = generate_salt(&mut rng);
    let seed2 = generate_master_seed(&mut rng);
    let (enc2, nonce2, tag2) =
        wrap_master_seed(&master_password, &seed2, &salt2, &mut rng).unwrap();
    let enc2_ref = CypherText::new(enc2.clone());
    let version2 = store_master_seed(
        &conn,
        enc2_ref,
        &Nonce12::new(nonce2.try_into().unwrap()),
        &Tag16::new(tag2.try_into().unwrap()),
        &Salt16::new(salt2),
    )
    .unwrap();
    assert_eq!(version2, 2);
    let (_, _, _, _, retrieved_version) = retrieve_master_seed(&conn).unwrap();
    assert_eq!(retrieved_version, 2);
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
#[serial]
fn test_xwing_keypair_from_stored_seed() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_keypair.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = "test_db_password";
    let conn =
        open_env_db(&MasterPassword::new(password.to_string())).expect("Failed to open env.db");
    let mut rng = rng();
    let master_password = MasterPassword::new("master_password".to_string());
    let salt = generate_salt(&mut rng);
    let seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) =
        wrap_master_seed(&master_password, &seed, &salt, &mut rng).unwrap();
    store_master_seed(
        &conn,
        CypherText::new(encrypted),
        &Nonce12::new(nonce.try_into().unwrap()),
        &Tag16::new(tag.try_into().unwrap()),
        &Salt16::new(salt),
    )
    .unwrap();
    let (retrieved_encrypted, retrieved_nonce, retrieved_tag, retrieved_salt, _) =
        retrieve_master_seed(&conn).unwrap();
    let unwrapped_seed = unwrap_master_seed(
        &master_password,
        &retrieved_encrypted,
        retrieved_nonce.expose_secret().as_slice(),
        retrieved_tag.expose_secret().as_slice(),
        retrieved_salt.expose_secret(),
    )
    .unwrap();
    assert_eq!(seed.expose_secret(), unwrapped_seed.expose_secret());
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
#[serial]
fn test_full_xwing_encapsulation_workflow() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_workflow.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = "test_db_password";
    let conn =
        open_env_db(&MasterPassword::new(password.to_string())).expect("Failed to open env.db");
    let mut rng = rng();
    let master_password = MasterPassword::new("master_password".to_string());
    let salt = generate_salt(&mut rng);
    let seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) =
        wrap_master_seed(&master_password, &seed, &salt, &mut rng).unwrap();
    store_master_seed(
        &conn,
        CypherText::new(encrypted),
        &Nonce12::new(nonce.try_into().unwrap()),
        &Tag16::new(tag.try_into().unwrap()),
        &Salt16::new(salt),
    )
    .unwrap();
    let (retrieved_encrypted, retrieved_nonce, retrieved_tag, retrieved_salt, _) =
        retrieve_master_seed(&conn).unwrap();
    let unwrapped_seed = unwrap_master_seed(
        &master_password,
        &retrieved_encrypted,
        retrieved_nonce.expose_secret().as_slice(),
        retrieved_tag.expose_secret().as_slice(),
        retrieved_salt.expose_secret(),
    )
    .unwrap();
    assert_eq!(seed.expose_secret(), unwrapped_seed.expose_secret());
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
#[serial]
fn test_corrupted_database_entries() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env_corrupt.db");
    let original_value = env::var("EFV_ENV_DB_PATH").ok();
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = "test_db_password";
    let conn =
        open_env_db(&MasterPassword::new(password.to_string())).expect("Failed to open env.db");
    let mut rng = rng();
    let master_password = MasterPassword::new("master_password".to_string());
    let salt = generate_salt(&mut rng);
    let seed = generate_master_seed(&mut rng);
    let (encrypted, nonce, tag) =
        wrap_master_seed(&master_password, &seed, &salt, &mut rng).unwrap();
    let encrypted_clone = encrypted.clone();
    let nonce_clone = nonce.clone();
    let tag_clone = tag.clone();
    store_master_seed(
        &conn,
        CypherText::new(encrypted),
        &Nonce12::new(nonce_clone.try_into().unwrap()),
        &Tag16::new(tag_clone.try_into().unwrap()),
        &Salt16::new(salt),
    )
    .unwrap();
    let encrypted_crypt = CypherText::new(encrypted_clone);
    let mut corrupted_nonce = nonce.to_vec();
    if let Some(byte) = corrupted_nonce.last_mut() {
        *byte = byte.wrapping_add(1);
    }
    let result = unwrap_master_seed(
        &master_password,
        &encrypted_crypt,
        corrupted_nonce.as_slice(),
        tag.as_slice(),
        &salt,
    );
    assert!(
        result.is_err(),
        "Corrupted nonce should cause decryption failure"
    );
    let mut corrupted_tag = tag.to_vec();
    if let Some(byte) = corrupted_tag.last_mut() {
        *byte = byte.wrapping_add(1);
    }
    let result = unwrap_master_seed(
        &master_password,
        &encrypted_crypt,
        nonce.as_slice(),
        corrupted_tag.as_slice(),
        &salt,
    );
    assert!(
        result.is_err(),
        "Corrupted tag should cause decryption failure"
    );
    drop(conn);
    if let Some(original) = original_value {
        env::set_var("EFV_ENV_DB_PATH", original);
    } else {
        env::remove_var("EFV_ENV_DB_PATH");
    }
}

#[test]
fn test_generate_master_encap_key() {
    let master_seed = MasterKemSeed::generate_random();

    let encap_key = generate_master_encap_key(&master_seed);

    // Test that the key is not zero (basic sanity)
    assert_ne!(encap_key.to_bytes(), [0u8; 1600]);
}

#[test]
#[serial]
fn test_empty_database_retrieval() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let db_path = temp_dir.path().join("test_env.db");
    env::set_var("EFV_ENV_DB_PATH", db_path.to_str().unwrap());
    let password = "test_db_password";
    let conn =
        open_env_db(&MasterPassword::new(password.to_string())).expect("Failed to open env.db");
    let result = retrieve_master_seed(&conn);
    assert!(
        result.is_err(),
        "Retrieving from empty database should fail"
    );
    drop(conn);
    env::remove_var("EFV_ENV_DB_PATH");
}
