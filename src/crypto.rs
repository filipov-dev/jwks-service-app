//! This module provides cryptographic functionality for generating JSON Web Keys (JWKs).
//!
//! Supports generation of RSA, Elliptic Curve (EC), and Edwards-curve Digital Signature Algorithm (EdDSA)
//! key pairs along with their JWK representations. RSA keys include X.509 certificate information.

use std::error::Error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openssl::bn::{BigNum, BigNumContext, BigNumRef};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Name, X509};
use sha1::{Sha1, Digest};
use uuid::Uuid;
use crate::models::{JwkData};

/// Generates an RSA key pair and associated JWK data including X.509 certificate information.
///
/// # Arguments
///
/// * `key_size` - RSA key size in bits (e.g., 2048). Recommended minimum is 2048 for production use.
/// * `alg` - Signing algorithm to use. Supported values: "RS256", "RS384", "RS512".
///
/// # Returns
///
/// Returns a [`JwkData`] structure containing:
/// - Public key components (n, e) in Base64URL format
/// - X.509 certificate chain (x5c)
/// - Certificate thumbprint (x5t)
/// - Private key in PKCS#8 format
/// - Generated key ID (kid)
///
/// # Errors
///
/// Returns an error if:
/// - Unsupported algorithm is specified
/// - OpenSSL operations fail during key generation or certificate creation
pub fn generate_rsa_jwk_data(key_size: u32, alg: &str) -> Result<JwkData, Box<dyn Error>> {
    let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
    let pkey = PKey::from_rsa(rsa.clone()).expect("Failed to generate PEM");

    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, "ANONYMOUS")?;
    let name = name.build();

    let digest = match alg {
        "RS256" => { openssl::hash::MessageDigest::sha256() }
        "RS384" => { openssl::hash::MessageDigest::sha384() }
        "RS512" => { openssl::hash::MessageDigest::sha512() }
        _ => { return Err(Box::from("Unsupported algorithm")) }
    };

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    cert_builder.set_subject_name(&name)?;
    cert_builder.set_issuer_name(&name)?;
    cert_builder.set_pubkey(&pkey)?;
    cert_builder.sign(&pkey, digest)?;
    let cert = cert_builder.build();

    let n = Some(URL_SAFE_NO_PAD.encode(rsa.n().to_vec()));
    let e = Some(URL_SAFE_NO_PAD.encode(rsa.e().to_vec()));
    let x5c = Some(vec![URL_SAFE_NO_PAD.encode(cert.to_der()?)]);

    let der = cert.to_der()?;
    let mut hasher = Sha1::new();
    hasher.update(&der);
    let x5t = Some(URL_SAFE_NO_PAD.encode(hasher.finalize()));

    let kid = Uuid::new_v4().to_string();

    let private_key_pem = pkey.private_key_to_pkcs8()?;
    let private_key_base64 = URL_SAFE_NO_PAD.encode(private_key_pem.clone());

    let alg = alg.to_string();

    Ok(JwkData {
        id: Default::default(),
        alg,
        kty: "RSA".to_string(),
        x5c,
        crv: None,
        x: None,
        y: None,
        n,
        e,
        kid,
        x5t,
        private_key: private_key_base64,
        created_at: Default::default(),
        deleted_at: None,
        private_key_expires_at: None,
        key_expires_at: None,
    })
}

#[test]
fn test_is_rsa_key_valid_rs256() {
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_rsa_jwk_data(1024, "RS256").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let jwk_n = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.n.unwrap()).unwrap()).unwrap();
    let jwk_e = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.e.unwrap()).unwrap()).unwrap();

    let rsa_public_key = Rsa::from_public_components(jwk_n, jwk_e).unwrap();
    let pkey_public = PKey::from_rsa(rsa_public_key).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

#[test]
fn test_is_rsa_key_valid_rs384() {
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_rsa_jwk_data(1024, "RS384").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let jwk_n = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.n.unwrap()).unwrap()).unwrap();
    let jwk_e = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.e.unwrap()).unwrap()).unwrap();

    let rsa_public_key = Rsa::from_public_components(jwk_n, jwk_e).unwrap();
    let pkey_public = PKey::from_rsa(rsa_public_key).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

#[test]
fn test_is_rsa_key_valid_rs512() {
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_rsa_jwk_data(1024, "RS512").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let jwk_n = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.n.unwrap()).unwrap()).unwrap();
    let jwk_e = BigNum::from_slice(&*URL_SAFE_NO_PAD.decode(jwk.e.unwrap()).unwrap()).unwrap();

    let rsa_public_key = Rsa::from_public_components(jwk_n, jwk_e).unwrap();
    let pkey_public = PKey::from_rsa(rsa_public_key).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

/// Generates an Elliptic Curve key pair and associated JWK data.
///
/// # Arguments
///
/// * `alg` - Signing algorithm to use. Supported values:
///   - "ES256" for P-256 curve
///   - "ES384" for P-384 curve
///   - "ES512" for P-521 curve
///
/// # Returns
///
/// Returns a [`JwkData`] structure containing:
/// - Elliptic curve parameters (crv)
/// - Public key coordinates (x, y) in Base64URL format
/// - Generated key ID (kid)
///
/// # Errors
///
/// Returns an error if:
/// - Unsupported algorithm is specified
/// - OpenSSL operations fail during key generation
/// - Coordinate extraction fails
///
/// # Note
///
/// EC keys do not include X.509 certificate information in this implementation.
pub fn generate_ec_jwk_data(alg: &str) -> Result<JwkData, Box<dyn Error>> {
    let curve = match alg {
        "ES256" => { Nid::X9_62_PRIME256V1 }
        "ES384" => { Nid::SECP384R1 }
        "ES512" => { Nid::SECP521R1 }
        _ => { return Err(Box::from("Unsupported algorithm")) }
    };

    let group = EcGroup::from_curve_name(curve)?;
    let ec_key = EcKey::generate(&group)?;

    let mut ctx = BigNumContext::new()?;
    let mut x = BigNum::new()?;
    let mut y = BigNum::new()?;
    let pub_key = ec_key.public_key();
    pub_key.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;

    let kid = Uuid::new_v4().to_string();

    let encode_coord = |bn: &BigNumRef| -> String {
        let bytes = bn.to_vec();
        URL_SAFE_NO_PAD.encode(bytes)
    };

    let crv = match alg {
        "ES256" => { "P-256".to_string() }
        "ES384" => { "P-384".to_string() }
        "ES512" => { "P-521".to_string() }
        _ => { return Err(Box::from("Unsupported algorithm")) }
    };

    let alg = alg.to_string();

    let private_key_pem = PKey::from_ec_key(ec_key)?.private_key_to_pkcs8()?;
    let private_key_base64 = URL_SAFE_NO_PAD.encode(private_key_pem.clone());
    
    Ok(JwkData {
        id: Default::default(),
        kty: "EC".to_string(),
        alg,
        kid,
        crv: Some(crv),
        x: Some(encode_coord(&x)),
        y: Some(encode_coord(&y)),
        n: None,
        e: None,
        x5c: None,
        x5t: None,
        private_key: private_key_base64,
        created_at: Default::default(),
        deleted_at: None,
        private_key_expires_at: None,
        key_expires_at: None,
    })
}

#[test]
fn test_is_ec_key_valid_es256() {
    use openssl::ec::{EcPoint};
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_ec_jwk_data("ES256").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();

    let x_bytes = URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();
    let y_bytes = URL_SAFE_NO_PAD.decode(jwk.y.unwrap()).unwrap();

    // Конвертируем байты в BigNum
    let x_bn = BigNum::from_slice(&*x_bytes).unwrap();
    let y_bn = BigNum::from_slice(&*y_bytes).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx).unwrap();

    let ec_key_public = EcKey::from_public_key(&group, &point).unwrap();

    let pkey_public = PKey::from_ec_key(ec_key_public).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

#[test]
fn test_is_ec_key_valid_es384() {
    use openssl::ec::{EcPoint};
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_ec_jwk_data("ES384").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();

    let x_bytes = URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();
    let y_bytes = URL_SAFE_NO_PAD.decode(jwk.y.unwrap()).unwrap();

    // Конвертируем байты в BigNum
    let x_bn = BigNum::from_slice(&*x_bytes).unwrap();
    let y_bn = BigNum::from_slice(&*y_bytes).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx).unwrap();

    let ec_key_public = EcKey::from_public_key(&group, &point).unwrap();

    let pkey_public = PKey::from_ec_key(ec_key_public).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

#[test]
fn test_is_ec_key_valid_es512() {
    use openssl::ec::{EcPoint};
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_ec_jwk_data("ES512").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();

    let x_bytes = URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();
    let y_bytes = URL_SAFE_NO_PAD.decode(jwk.y.unwrap()).unwrap();

    // Конвертируем байты в BigNum
    let x_bn = BigNum::from_slice(&*x_bytes).unwrap();
    let y_bn = BigNum::from_slice(&*y_bytes).unwrap();

    let mut ctx = BigNumContext::new().unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.set_affine_coordinates_gfp(&group, &x_bn, &y_bn, &mut ctx).unwrap();

    let ec_key_public = EcKey::from_public_key(&group, &point).unwrap();

    let pkey_public = PKey::from_ec_key(ec_key_public).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

/// Generates an EdDSA key pair and associated JWK data.
///
/// # Arguments
///
/// * `crv` - Edwards curve to use. Supported values:
///   - "Ed25519" for Ed25519 curve
///   - "Ed448" for Ed448 curve
///
/// # Returns
///
/// Returns a [`JwkData`] structure containing:
/// - Public key (x) in Base64URL format
/// - Curve identifier (crv)
/// - Private key in PKCS#8 format
/// - Generated key ID (kid)
///
/// # Errors
///
/// Returns an error if:
/// - Unsupported curve is specified
/// - OpenSSL operations fail during key generation
pub fn generate_eddsa_jwk_data(crv: &str) -> Result<JwkData, Box<dyn Error>> {
    let pkey = match crv {
        "Ed25519" => { PKey::generate_ed25519()? }
        "Ed448" => { PKey::generate_ed448()? }
        _ => { return Err(Box::from("Unsupported algorithm")) }
    };

    let public_key_bytes = pkey.raw_public_key()?;
    let x = Some(URL_SAFE_NO_PAD.encode(public_key_bytes));

    let kid = Uuid::new_v4().to_string();

    let private_key_pem = pkey.private_key_to_pkcs8()?;
    let private_key_base64 = URL_SAFE_NO_PAD.encode(private_key_pem.clone());

    let crv = Some(crv.to_string());

    Ok(JwkData {
        id: Default::default(),
        kty: "OKP".to_string(),
        alg: "EdDSA".to_string(),
        crv,
        kid,
        x,
        y: None,
        n: None,
        e: None,
        x5c: None,
        x5t: None,
        private_key: private_key_base64,
        created_at: Default::default(),
        deleted_at: None,
        private_key_expires_at: None,
        key_expires_at: None,
    })
}

#[test]
fn test_is_eddsa_key_valid_ed25519() {
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_eddsa_jwk_data("Ed25519").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let jwk_x = &*URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();

    let pkey_public = PKey::public_key_from_raw_bytes(&jwk_x, openssl::pkey::Id::ED25519).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}

#[test]
fn test_is_eddsa_key_valid_ed448() {
    use openssl::sign::{Signer, Verifier};

    let jwk: JwkData = generate_eddsa_jwk_data("Ed448").unwrap();

    let control_data = "CONTROL_TEXT";

    let pkey_private = {
        let new_private_key = URL_SAFE_NO_PAD.decode(jwk.private_key.clone()).unwrap();
        PKey::private_key_from_pkcs8(&*new_private_key)
    }.unwrap();

    let mut signer = Signer::new_without_digest(&pkey_private).unwrap();
    let signature = signer.sign_oneshot_to_vec(control_data.as_bytes()).unwrap();

    let jwk_x = &*URL_SAFE_NO_PAD.decode(jwk.x.unwrap()).unwrap();

    let pkey_public = PKey::public_key_from_raw_bytes(&jwk_x, openssl::pkey::Id::ED448).unwrap();

    let mut verifier = Verifier::new_without_digest(&pkey_public).unwrap();
    let result = verifier.verify_oneshot(&signature, control_data.as_bytes()).unwrap();

    assert_eq!(result, true);
}