//! Микросервис для работы с JWK (JSON Web Key).
//!
//! Этот микросервис предоставляет endpoint для получения JWK в формате JSON.
//! Ключи хранятся в базе данных PostgreSQL, а для работы с базой данных используется Diesel.

use actix_web::*;
use uuid::Uuid;
use diesel::prelude::*;
use crate::models::*;
use crate::schema::jwks::dsl::*;
use crate::db::establish_connection;
use crate::crypto::{generate_rsa_keypair, generate_ec_keypair, generate_ed25519_keypair};
use openssl::nid::Nid;

mod models;
mod schema;
mod db;
mod crypto;

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

    // Убираем приватный ключ из ответа
    let public_jwks = results.into_iter().map(|jwk| Jwk {
        id: jwk.id,
        kty: jwk.kty,
        alg: jwk.alg,
        kid: jwk.kid,
        n: jwk.n,
        e: jwk.e,
        d: "".to_string(), // Приватный ключ не возвращаем
    }).collect::<Vec<_>>();

    let jwks_list = Jwks {
        keys: public_jwks,
    };

    HttpResponse::Ok().json(jwks_list)
}

/// Обработчик для генерации JWK.
///
/// # Аргументы
///
/// * `input` - Входные данные с названием алгоритма.
///
/// # Возвращает
///
/// Возвращает статус `201 Created`, если ключ успешно сгенерирован и сохранен.
///
/// # Пример
///
/// ```bash
/// curl -X POST -H "Content-Type: application/json" -d '{"alg": "RS256"}' http://localhost:8080/jwks
/// ```
async fn add_jwk_handler(input: web::Json<AlgorithmInput>) -> impl Responder {
    let algorithm = &input.alg;

    // Генерация ключей в зависимости от алгоритма
    let (public_key, private_key) = match algorithm.as_str() {
        "RS256" | "RS384" | "RS512" => generate_rsa_keypair(2048),
        "ES256" => generate_ec_keypair(Nid::X9_62_PRIME256V1),
        "ES384" => generate_ec_keypair(Nid::SECP384R1),
        "ES512" => generate_ec_keypair(Nid::SECP521R1),
        "Ed25519" => generate_ed25519_keypair(),
        _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
    };

    // Создание JWK
    let jwk = Jwk {
        id: String::from(Uuid::new_v4()),
        kty: match algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => "RSA".to_string(),
            "ES256" | "ES384" | "ES512" => "EC".to_string(),
            "Ed25519" => "OKP".to_string(), // Octet Key Pair (Ed25519)
            _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
        },
        alg: algorithm.clone(),
        kid: Uuid::new_v4().to_string(), // Уникальный идентификатор ключа
        n: public_key, // Модуль ключа (публичный ключ)
        e: match algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => "AQAB".to_string(), // Публичная экспонента для RSA
            _ => "".to_string(), // Для EC и Ed25519 это поле не используется
        },
        d: private_key, // Приватный ключ
    };

    // Сохранение JWK в базу данных
    let connection = &mut establish_connection();
    diesel::insert_into(jwks)
        .values(&jwk)
        .execute(connection)
        .expect("Error saving new jwk");

    HttpResponse::Created().json(jwk)
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