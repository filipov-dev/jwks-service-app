//! Микросервис для работы с JWK (JSON Web Key).
//!
//! Этот микросервис предоставляет endpoint для получения JWK в формате JSON.
//! Ключи хранятся в базе данных PostgreSQL, а для работы с базой данных используется Diesel.

use actix_web::*;
use serde::*;
use diesel::prelude::*;
use crate::models::*;
use crate::schema::jwks::dsl::*;
use crate::db::establish_connection;

mod models;
mod schema;
mod db;

/// Обработчик для получения JWK.
///
/// # Возвращает
///
/// Возвращает JSON с набором JWK.
///
/// # Пример
///
/// ```bash
/// curl http://localhost:8080/.well-known/jwks.json
/// ```
async fn jwks_handler() -> impl Responder {
    let connection = &mut establish_connection();
    let results = jwks
        .load::<Jwk>(connection)
        .expect("Error loading jwks");

    let jwks_list = Jwks {
        keys: results,
    };

    HttpResponse::Ok().json(jwks_list)
}

/// Обработчик для добавления нового JWK.
///
/// # Аргументы
///
/// * `new_jwk` - Новый JWK в формате JSON.
///
/// # Возвращает
///
/// Возвращает статус `201 Created`, если ключ успешно добавлен.
///
/// # Пример
///
/// ```bash
/// curl -X POST -H "Content-Type: application/json" -d '{"id": "550e8400-e29b-41d4-a716-446655440000", "kty": "RSA", "alg": "RS256", "kid": "1", "n": "some_base64_encoded_modulus", "e": "some_base64_encoded_exponent"}' http://localhost:8080/jwks
/// ```
async fn add_jwk_handler(new_jwk: web::Json<Jwk>) -> impl Responder {
    let connection = &mut establish_connection();
    diesel::insert_into(jwks)
        .values(&new_jwk.into_inner())
        .execute(connection)
        .expect("Error saving new jwk");

    HttpResponse::Created().body("JWK added")
}

/// Точка входа в приложение.
///
/// Запускает веб-сервер на `127.0.0.1:8080`.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/.well-known/jwks.json", web::get().to(jwks_handler))
            .route("/jwks", web::post().to(add_jwk_handler))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}