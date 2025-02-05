//! Микросервис для работы с JWK (JSON Web Key).
//!
//! Этот микросервис предоставляет endpoint для получения JWK в формате JSON.
//! Ключи хранятся в базе данных PostgreSQL, а для работы с базой данных используется Diesel.

use actix_web::*;
use actix_cors::Cors;
use uuid::Uuid;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use crate::models::*;
use crate::schema::jwks::dsl::*;
use crate::db::establish_connection;
use crate::crypto::{generate_rsa_keypair, generate_ec_keypair, generate_ed25519_keypair};
use openssl::nid::Nid;
use std::env;
use utoipa::OpenApi;

mod models;
mod schema;
mod db;
mod crypto;

// Встроенные миграции
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(OpenApi)]
#[openapi(
    paths(
        jwks_handler,
        add_jwk_handler
    ),
    components(
        schemas(Jwk, Jwks, AlgorithmInput)
    ),
    tags(
        (name = "JWK Service", description = "API for managing JSON Web Keys")
    )
)]
struct ApiDoc;

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
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "Список JWK", body = Jwks)
    )
)]
pub async fn jwks_handler() -> impl Responder {
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
#[utoipa::path(
    post,
    path = "/jwks",
    request_body = AlgorithmInput,
    responses(
        (status = 201, description = "JWK успешно добавлен", body = Jwk)
    )
)]
pub async fn add_jwk_handler(input: web::Json<AlgorithmInput>) -> impl Responder {
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
        id: Uuid::new_v4(),
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

/// Эндпоинт для предоставления OpenAPI-спецификации
async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(ApiDoc::openapi().to_json().unwrap())
}

/// Точка входа в приложение.
///
/// Запускает веб-сервер на `0.0.0.0:8080`.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Проверяем, нужно ли выполнять миграции
    if env::var("RUN_MIGRATIONS_ON_START").unwrap_or_default() == "1" {
        let connection = &mut db::establish_connection();
        println!("Running migrations...");

        // Выполняем миграции
        connection.run_pending_migrations(MIGRATIONS).expect("Failed to run migrations");

        // Получаем список применённых миграций
        let applied_migrations = connection.applied_migrations().expect("Failed to get applied migrations");
        println!("Applied migrations:");
        for migration in applied_migrations {
            println!("- {}", migration);
        }

        println!("Migrations completed.");
    }

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()  // Разрешаем запросы с любого источника
            .allowed_methods(vec!["GET", "POST"])  // Разрешаем GET и POST
            .allow_any_header()  // Разрешаем любые заголовки
            .max_age(3600);  // Устанавливаем время кэширования CORS

        App::new()
            .wrap(cors) // Добавляем middleware CORS
            .route("/.well-known/jwks.json", web::get().to(jwks_handler))
            .route("/jwks", web::post().to(add_jwk_handler))
            .route("/api-docs/openapi.json", web::get().to(openapi_spec)) // Эндпоинт для OpenAPI-спецификации
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}