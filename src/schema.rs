//! Схема базы данных для таблицы `jwks`.

diesel::table! {
    /// Таблица для хранения JWK.
    jwks (id) {
        /// Уникальный идентификатор ключа.
        id -> Uuid,
        /// Тип ключа (например, "RSA").
        kty -> Varchar,
        /// Алгоритм, используемый с ключом (например, "RS256").
        alg -> Varchar,
        /// Идентификатор ключа (Key ID).
        kid -> Varchar,
        /// Модуль ключа в формате Base64.
        n -> Text,
        /// Публичная экспонента ключа в формате Base64.
        e -> Text,
        /// Приватный ключ в формате Base64.
        d -> Text,
    }
}