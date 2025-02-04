use openssl::rsa::Rsa;
use openssl::pkey::Private;
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