use diesel::{Insertable, Queryable};
use serde::*;

/// Структура для входных данных эндпоинта `/jwks`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AlgorithmInput {
    /// Название алгоритма (например, "RS256").
    pub alg: String,
}

/// Представляет собой один JWK (JSON Web Key).
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable)]
#[diesel(table_name = crate::schema::jwks)]
pub struct Jwk {
    /// Уникальный идентификатор ключа.
    pub id: String,
    /// Тип ключа (например, "RSA").
    pub kty: String,
    /// Алгоритм, используемый с ключом (например, "RS256").
    pub alg: String,
    /// Идентификатор ключа (Key ID).
    pub kid: String,
    /// Модуль ключа в формате Base64.
    pub n: String,
    /// Публичная экспонента ключа в формате Base64.
    pub e: String,
    /// Приватный ключ в формате Base64.
    pub d: String,
}

/// Представляет собой набор JWK.
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwks {
    /// Список JWK.
    pub keys: Vec<Jwk>,
}