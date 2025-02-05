use diesel::{Insertable, Queryable};
use serde::*;
use utoipa::ToSchema;
use uuid::Uuid;
use chrono::NaiveDateTime;

/// Структура для входных данных эндпоинта `/jwks`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AlgorithmInput {
    /// Название алгоритма (например, "RS256", "ES256", "Ed25519").
    ///
    /// Возможные значения:
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

/// Представляет собой один JWK (JSON Web Key).
#[derive(Debug, Serialize, Deserialize, Queryable, Insertable, ToSchema)]
#[diesel(table_name = crate::schema::jwks)]
pub struct Jwk {
    /// Уникальный идентификатор ключа.
    #[schema(value_type = String)]  // Указываем, что Uuid сериализуется как строка
    pub id: Uuid,
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
    /// Дата создания ключа.
    #[serde(skip_serializing)]  // Поле не будет возвращаться в ответах API
    #[schema(value_type = String)]  // Указываем, что NaiveDateTime сериализуется как строка
    pub created_at: NaiveDateTime,
    /// Дата удаления ключа. Если `None`, ключ активен.
    #[serde(skip_serializing)]  // Поле не будет возвращаться в ответах API
    pub deleted_at: Option<NaiveDateTime>,
    /// Время протухания приватного ключа.
    #[serde(skip_serializing)]  // Поле не будет возвращаться в ответах API
    pub private_key_expires_at: Option<NaiveDateTime>,
    /// Время протухания всего ключа.
    #[serde(skip_serializing)]  // Поле не будет возвращаться в ответах API
    pub key_expires_at: Option<NaiveDateTime>,
}

/// Представляет собой набор JWK.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Jwks {
    /// Список JWK.
    pub keys: Vec<Jwk>,
}