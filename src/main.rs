//! Микросервис для работы с JWK (JSON Web Key).
//!
//! Этот микросервис предоставляет endpoint для получения JWK в формате JSON.
//! Ключи хранятся в базе данных PostgreSQL, а для работы с базой данных используется Diesel.

use actix_web::*;
use actix_cors::Cors;
use diesel::prelude::*;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use crate::models::*;
use crate::handlers::*;
use dotenv::dotenv;
use std::env;
use utoipa::OpenApi;

mod models;
mod schema;
mod db;
mod crypto;
mod handlers;

// Встроенные миграции
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(OpenApi)]
#[openapi(
    paths(
        jwks_handler,
        get_jwk_by_id_handler,
        add_jwk_handler,
        delete_jwk_handler
    ),
    components(
        schemas(Jwk, Jwks, AlgorithmInput)
    ),
    tags(
        (name = "JWK Service", description = "API for managing JSON Web Keys")
    )
)]
struct ApiDoc;

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
    dotenv().ok();

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
            .allowed_methods(vec!["GET", "POST", "DELETE"])  // Разрешаем GET и POST
            .allow_any_header()  // Разрешаем любые заголовки
            .max_age(3600);  // Устанавливаем время кэширования CORS

        App::new()
            .wrap(cors) // Добавляем middleware CORS
            .route("/.well-known/jwks.json", web::get().to(jwks_handler))

            .route("/jwks", web::post().to(add_jwk_handler))
            .route("/jwks/{id}", web::get().to(get_jwk_by_id_handler))  // Эндпоинт для получения ключа по ID
            .route("/jwks/{id}", web::delete().to(delete_jwk_handler))  // Эндпоинт для удаления ключа

            .route("/api-docs/openapi.json", web::get().to(openapi_spec)) // Эндпоинт для OpenAPI-спецификации
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}