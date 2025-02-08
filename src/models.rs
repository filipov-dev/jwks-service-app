//! This module defines the data models used in the JWK microservice.

use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable};
use serde::*;
use utoipa::ToSchema;
use uuid::Uuid;

/// Input data for the `/jwks` endpoint.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AlgorithmInput {
    /// Algorithm name:
    ///
    /// - `RS256`
    /// - `RS384`
    /// - `RS512`
    /// - `ES256`
    /// - `ES384`
    /// - `ES512`
    /// - `Ed25519`
    #[schema(example = "RS256")]
    pub alg: String,
}

/// Represents a single JWK (JSON Web Key).
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, ToSchema)]
#[diesel(table_name = crate::schema::jwks)]
pub struct Jwk {
    /// Unique key identifier.
    #[schema(value_type = String)] // Indicates that Uuid is serialized as a string
    pub id: Uuid,
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// Algorithm used with the key (e.g., "RS256").
    pub alg: String,
    /// Key ID.
    pub kid: String,
    /// Key modulus in Base64 format.
    pub n: String,
    /// Public exponent in Base64 format.
    pub e: String,
    /// Private key in Base64 format.
    pub d: String,
}

/// Represents a single JWK (JSON Web Key) with additional
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, ToSchema)]
#[diesel(table_name = crate::schema::jwks)]
pub struct JwkData {
    /// Unique key identifier.
    #[schema(value_type = String)] // Indicates that Uuid is serialized as a string
    pub id: Uuid,
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// Algorithm used with the key (e.g., "RS256").
    pub alg: String,
    /// Key ID.
    pub kid: String,
    /// Key modulus in Base64 format.
    pub n: String,
    /// Public exponent in Base64 format.
    pub e: String,
    /// Private key in Base64 format.
    pub d: String,
    /// Key creation date.
    #[serde(skip_serializing)] // Field will not be returned in API responses
    #[schema(value_type = String)] // Indicates that NaiveDateTime is serialized as a string
    pub created_at: NaiveDateTime,
    /// Key deletion date. If `None`, the key is active.
    #[serde(skip_serializing)] // Field will not be returned in API responses
    pub deleted_at: Option<NaiveDateTime>,
    /// Private key expiration date.
    #[serde(skip_serializing)] // Field will not be returned in API responses
    pub private_key_expires_at: Option<NaiveDateTime>,
    /// Key expiration date.
    #[serde(skip_serializing)] // Field will not be returned in API responses
    pub key_expires_at: Option<NaiveDateTime>,
}

/// Represents a set of JWKs.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Jwks {
    /// List of JWKs.
    pub keys: Vec<Jwk>,
}
