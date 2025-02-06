//! This module contains the request handlers for the JWK microservice.

use dotenv::dotenv;
use std::env;
use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use diesel::prelude::*;
use openssl::nid::Nid;
use uuid::Uuid;
use crate::crypto::{generate_ec_keypair, generate_ed25519_keypair, generate_rsa_keypair};
use crate::db::establish_connection;
use crate::models::{AlgorithmInput, Jwk, Jwks};
use crate::schema::jwks::dsl::*;

/// Handles the request to retrieve a list of active JWKs.
///
/// # Returns
///
/// A JSON response containing the list of active JWKs.
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "Список JWK", body = Jwks)
    )
)]
pub async fn jwks_handler() -> impl Responder {
    let connection = &mut establish_connection();

    // Return only active keys (deleted_at IS NULL and key_expires_at > NOW)
    let results = jwks
        .filter(deleted_at.is_null())
        .filter(key_expires_at.gt(Utc::now().naive_utc()))
        .load::<Jwk>(connection)
        .expect("Error loading jwks");

    let public_jwks = results.into_iter().map(|jwk| Jwk {
        id: jwk.id,
        kty: jwk.kty,
        alg: jwk.alg,
        kid: jwk.kid,
        n: jwk.n,
        e: jwk.e,
        d: "".to_string(),
        created_at: jwk.created_at,
        deleted_at: None,
        private_key_expires_at: None,
        key_expires_at: None,
    }).collect::<Vec<_>>();

    let jwks_list = Jwks {
        keys: public_jwks,
    };

    HttpResponse::Ok().json(jwks_list)
}

/// Handles the request to add a new JWK.
///
/// # Arguments
///
/// * `input` - The input data containing the algorithm for key generation.
///
/// # Returns
///
/// A JSON response containing the newly created JWK.
#[utoipa::path(
    post,
    path = "/jwks",
    request_body = AlgorithmInput,
    responses(
        (status = 201, description = "JWK successfully added", body = Jwk)
    )
)]
pub async fn add_jwk_handler(input: web::Json<AlgorithmInput>) -> impl Responder {
    dotenv().ok();

    let algorithm = &input.alg;

    // Get expiration times from environment variables
    let private_key_expiration_seconds: i64 = env::var("PRIVATE_KEY_EXPIRATION_SECONDS")
        .unwrap_or_else(|_| "86400".to_string())  // По умолчанию 1 день
        .parse()
        .expect("PRIVATE_KEY_EXPIRATION_SECONDS must be a number");

    let key_expiration_seconds: i64 = env::var("KEY_EXPIRATION_SECONDS")
        .unwrap_or_else(|_| "172800".to_string())  // По умолчанию 2 дня
        .parse()
        .expect("KEY_EXPIRATION_SECONDS must be a number");

    // Generate keys based on the algorithm
    let (public_key, private_key) = match algorithm.as_str() {
        "RS256" | "RS384" | "RS512" => generate_rsa_keypair(2048),
        "ES256" => generate_ec_keypair(Nid::X9_62_PRIME256V1),
        "ES384" => generate_ec_keypair(Nid::SECP384R1),
        "ES512" => generate_ec_keypair(Nid::SECP521R1),
        "Ed25519" => generate_ed25519_keypair(),
        _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
    };

    // Current time
    let now = Utc::now().naive_utc();

    // Create a new JWK
    let jwk = Jwk {
        id: Uuid::new_v4(),
        kty: match input.alg.as_str() {
            "RS256" | "RS384" | "RS512" => "RSA".to_string(),
            "ES256" | "ES384" | "ES512" => "EC".to_string(),
            "Ed25519" => "OKP".to_string(), // Octet Key Pair (Ed25519)
            _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
        },
        alg: input.alg.clone(),
        kid: Uuid::new_v4().to_string(), // Unique key ID
        n: public_key, // Key modulus (public key)
        e: match input.alg.as_str() {
            "RS256" | "RS384" | "RS512" => "AQAB".to_string(), // Public exponent for RSA
            _ => "".to_string(), // Not used for EC and Ed25519
        },
        d: private_key, // Private key
        created_at: now,
        deleted_at: None,
        private_key_expires_at: Some(now + chrono::Duration::seconds(private_key_expiration_seconds)),
        key_expires_at: Some(now + chrono::Duration::seconds(private_key_expiration_seconds + key_expiration_seconds)),
    };

    // Save the JWK to the database
    let connection = &mut establish_connection();
    diesel::insert_into(jwks)
        .values(&jwk)
        .execute(connection)
        .expect("Error saving new jwk");

    HttpResponse::Created().json(jwk)
}

/// Handles the request to retrieve a JWK by its ID.
/// (including private part)
///
/// # Arguments
///
/// * `key_id` - The unique identifier of the key.
///
/// # Returns
///
/// A JSON response containing the JWK or an error message.
#[utoipa::path(
    get,
    path = "/jwks/{id}",
    params(
        ("id" = String, Path, description = "Unique key identifier")
    ),
    responses(
        (status = 200, description = "Key found", body = Jwk),
        (status = 404, description = "Key not found "),
        (status = 410, description = "Private key expired")
    )
)]
pub async fn get_jwk_by_id_handler(key_id: web::Path<Uuid>) -> impl Responder {
    let connection = &mut establish_connection();

    // Find the key by ID
    let result = jwks
        .filter(id.eq(key_id.into_inner()))
        .filter(deleted_at.is_null())  // Exclude deleted keys
        .filter(key_expires_at.gt(Utc::now().naive_utc()))  // Exclude expired keys
        .first::<Jwk>(connection);

    match result {
        Ok(jwk_result) => {
            // Check if the private key has expired
            let now = Utc::now().naive_utc();
            if let Some(expires_at) = jwk_result.private_key_expires_at {
                if now > expires_at {
                    return HttpResponse::Gone().body("Private key expired");
                }
            }

            HttpResponse::Ok().json(jwk_result)
        }
        Err(_) => HttpResponse::NotFound().body("Key not found"),
    }
}

/// Handles the request to delete a JWK (soft delete).
///
/// # Arguments
///
/// * `key_id` - The unique identifier of the key.
///
/// # Returns
///
/// A response indicating success or failure.
#[utoipa::path(
    delete,
    path = "/jwks/{id}",
    params(
        ("id" = String, Path, description = "Unique key identifier")
    ),
    responses(
        (status = 204, description = "Key successfully deleted"),
        (status = 404, description = "Key not found")
    )
)]
pub async fn delete_jwk_handler(key_id: web::Path<Uuid>) -> impl Responder {
    let connection = &mut establish_connection();

    // Set deleted_at to the current date and time
    let result = diesel::update(jwks.filter(id.eq(key_id.into_inner())))
        .set(deleted_at.eq(Some(Utc::now().naive_utc())))
        .execute(connection);

    match result {
        Ok(0) => HttpResponse::NotFound().body("Key not found"),
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(_) => HttpResponse::InternalServerError().body("Failed to delete key"),
    }
}