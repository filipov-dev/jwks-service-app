//! This module provides cryptographic functionality for generating keys.

use openssl::rsa::Rsa;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use base64;

/// Generates an RSA key pair and returns them in Base64 format.
///
/// # Arguments
///
/// * `key_size` - The size of the key in bits (e.g., 2048).
///
/// # Returns
///
/// A tuple containing the public key and private key in Base64 format.
pub fn generate_rsa_keypair(key_size: u32) -> (String, String) {
    let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
    let private_key = rsa.private_key_to_der().expect("Failed to serialize private key");
    let public_key = rsa.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}

/// Generates an EC key pair and returns them in Base64 format.
///
/// # Arguments
///
/// * `curve` - The elliptic curve to use (e.g., `Nid::X9_62_PRIME256V1` for P-256).
///
/// # Returns
///
/// A tuple containing the public key and private key in Base64 format.
pub fn generate_ec_keypair(curve: Nid) -> (String, String) {
    let group = EcGroup::from_curve_name(curve).expect("Failed to create EC group");
    let ec_key = EcKey::generate(&group).expect("Failed to generate EC key");
    let private_key = ec_key.private_key_to_der().expect("Failed to serialize private key");
    let public_key = ec_key.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}

/// Generates an Ed25519 key pair and returns them in Base64 format.
///
/// # Returns
///
/// A tuple containing the public key and private key in Base64 format.
pub fn generate_ed25519_keypair() -> (String, String) {
    let key = openssl::pkey::PKey::generate_ed25519().expect("Failed to generate Ed25519 key");
    let private_key = key.private_key_to_der().expect("Failed to serialize private key");
    let public_key = key.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}