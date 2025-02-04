use openssl::rsa::Rsa;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use base64;

/// Генерирует RSA-ключи и возвращает их в формате Base64.
///
/// # Аргументы
///
/// * `key_size` - Размер ключа в битах (например, 2048).
///
/// # Возвращает
///
/// Кортеж из (публичный ключ в формате Base64, приватный ключ в формате Base64).
pub fn generate_rsa_keypair(key_size: u32) -> (String, String) {
    let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
    let private_key = rsa.private_key_to_der().expect("Failed to serialize private key");
    let public_key = rsa.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}

/// Генерирует EC-ключи и возвращает их в формате Base64.
///
/// # Аргументы
///
/// * `curve` - Название кривой (например, "P-256", "P-384").
///
/// # Возвращает
///
/// Кортеж из (публичный ключ в формате Base64, приватный ключ в формате Base64).
pub fn generate_ec_keypair(curve: Nid) -> (String, String) {
    let group = EcGroup::from_curve_name(curve).expect("Failed to create EC group");
    let ec_key = EcKey::generate(&group).expect("Failed to generate EC key");
    let private_key = ec_key.private_key_to_der().expect("Failed to serialize private key");
    let public_key = ec_key.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}

/// Генерирует Ed25519-ключи и возвращает их в формате Base64.
///
/// # Возвращает
///
/// Кортеж из (публичный ключ в формате Base64, приватный ключ в формате Base64).
pub fn generate_ed25519_keypair() -> (String, String) {
    let key = openssl::pkey::PKey::generate_ed25519().expect("Failed to generate Ed25519 key");
    let private_key = key.private_key_to_der().expect("Failed to serialize private key");
    let public_key = key.public_key_to_der().expect("Failed to serialize public key");

    let private_key_b64 = base64::encode(&private_key);
    let public_key_b64 = base64::encode(&public_key);

    (public_key_b64, private_key_b64)
}