use crate::handlers::*;
use crate::models::*;
use actix_web::{web, HttpResponse, Responder};
use diesel_migrations::{embed_migrations, EmbeddedMigrations};
use utoipa::OpenApi;

pub mod crypto;
pub mod db;
pub mod handlers;
pub mod models;
pub mod schema;

// Embedded migrations
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// OpenAPI documentation for the JWK microservice
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

/// Endpoint to provide OpenAPI specification
pub async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(ApiDoc::openapi().to_json().unwrap())
}

/// Configure the Actix Web application
pub fn app_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/.well-known/jwks.json", web::get().to(jwks_handler))
            .route("/jwks", web::post().to(add_jwk_handler))
            .route("/jwks/{id}", web::get().to(get_jwk_by_id_handler))
            .route("/jwks/{id}", web::delete().to(delete_jwk_handler))
            .route("/api-docs/openapi.json", web::get().to(openapi_spec)),
    );
}
