//! This module defines the data models used in the JWK microservice.

use chrono::NaiveDateTime;
use diesel::{Insertable, Queryable, Selectable};
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
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Jwk {
    /// Key type (e.g., "RSA").
    pub kty: String,
    /// How the key was meant to be used; sig represents the signature.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm used with the key (e.g., "RS256").
    pub alg: String,
    /// Key ID.
    pub kid: String,
    /// Contain the subtype of the key (from the "JSON Web Elliptic Curve" registry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Contain the public key encoded using the base64url [RFC4648] encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Key modulus in Base64 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// Public exponent in Base64 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// The x.509 certificate chain.
    /// The first entry in the array is the certificate to use for token verification;
    /// the other certificates can be used to verify this first certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// The thumbprint of the x.509 cert (SHA-1 thumbprint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
}

/// Represents a single JWK (JSON Web Key) with additional
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, Selectable, ToSchema)]
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
    /// Contain the subtype of the key (from the "JSON Web Elliptic Curve" registry).
    pub crv: Option<String>,
    /// Contain the public key encoded using the base64url [RFC4648] encoding
    pub x: Option<String>,
    pub y: Option<String>,
    /// Key modulus in Base64 format.
    pub n: Option<String>,
    /// Public exponent in Base64 format.
    pub e: Option<String>,
    /// The x.509 certificate chain.
    /// The first entry in the array is the certificate to use for token verification;
    /// the other certificates can be used to verify this first certificate.
    pub x5c: Option<Vec<String>>,
    /// The thumbprint of the x.509 cert (SHA-1 thumbprint).
    pub x5t: Option<String>,
    /// Private key in Base64 format.
    pub private_key: String,
    /// Key creation date.
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
