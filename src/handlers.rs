//! This module contains the request handlers for the JWK microservice.

use crate::crypto::{generate_ec_jwk_data, generate_eddsa_jwk_data, generate_rsa_jwk_data};
use crate::db::establish_connection;
use crate::models::{AlgorithmInput, Jwk, JwkData, Jwks};
use crate::schema::jwks::dsl::*;
use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use uuid::Uuid;

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
        .load::<JwkData>(connection)
        .expect("Error loading jwks");

    let public_jwks = results
        .into_iter()
        .map(|jwk| Jwk {
            kty: jwk.kty,
            use_: "sig".to_string(),
            alg: jwk.alg,
            kid: jwk.kid,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            n: jwk.n,
            e: jwk.e,
            x5c: jwk.x5c,
            x5t: jwk.x5t,
        })
        .collect::<Vec<_>>();

    let jwks_list = Jwks { keys: public_jwks };

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
        .unwrap_or_else(|_| "86400".to_string()) // По умолчанию 1 день
        .parse()
        .expect("PRIVATE_KEY_EXPIRATION_SECONDS must be a number");

    let key_expiration_seconds: i64 = env::var("KEY_EXPIRATION_SECONDS")
        .unwrap_or_else(|_| "172800".to_string()) // По умолчанию 2 дня
        .parse()
        .expect("KEY_EXPIRATION_SECONDS must be a number");

    // Generate keys based on the algorithm
    let jwk_key = match algorithm.as_str() {
        "RS256" | "RS384" | "RS512" => generate_rsa_jwk_data(2048, algorithm.as_str()).unwrap(),
        "ES256" | "ES384" | "ES512" => generate_ec_jwk_data(algorithm.as_str()).unwrap(),
        "Ed25519" | "Ed448" => generate_eddsa_jwk_data(algorithm.as_str()).unwrap(),
        _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
    };

    // Current time
    let now = Utc::now().naive_utc();

    // Create a new JWK
    let jwk = JwkData {
        id: Uuid::new_v4(),
        kty: jwk_key.kty,
        alg: jwk_key.alg,
        crv: jwk_key.crv,
        kid: jwk_key.kid,
        x: jwk_key.x,
        y: jwk_key.y,
        n: jwk_key.n,
        e: jwk_key.e,
        x5c: jwk_key.x5c,
        x5t: jwk_key.x5t,
        private_key: jwk_key.private_key,
        created_at: now,
        deleted_at: None,
        private_key_expires_at: Some(
            now + chrono::Duration::seconds(private_key_expiration_seconds),
        ),
        key_expires_at: Some(
            now + chrono::Duration::seconds(
                private_key_expiration_seconds + key_expiration_seconds,
            ),
        ),
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
        (status = 200, description = "Key found", body = JwkData),
        (status = 404, description = "Key not found "),
        (status = 410, description = "Private key expired")
    )
)]
pub async fn get_jwk_by_id_handler(key_id: web::Path<Uuid>) -> impl Responder {
    let connection = &mut establish_connection();

    // Find the key by ID
    let result = jwks
        .filter(id.eq(key_id.into_inner()))
        .filter(deleted_at.is_null()) // Exclude deleted keys
        .filter(key_expires_at.gt(Utc::now().naive_utc())) // Exclude expired keys
        .first::<JwkData>(connection);

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
