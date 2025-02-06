//! This module contains the main application logic for the JWK microservice.

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
async fn openapi_spec() -> impl Responder {
    HttpResponse::Ok()
        .content_type("application/json")
        .body(ApiDoc::openapi().to_json().unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Check if migrations need to be run
    if env::var("RUN_MIGRATIONS_ON_START").unwrap_or_default() == "1" {
        let connection = &mut db::establish_connection();
        println!("Running migrations...");

        // Run migrations
        connection.run_pending_migrations(MIGRATIONS).expect("Failed to run migrations");

        // Get the list of applied migrations
        let applied_migrations = connection.applied_migrations().expect("Failed to get applied migrations");
        println!("Applied migrations:");
        for migration in applied_migrations {
            println!("- {}", migration);
        }

        println!("Migrations completed.");
    }

    // Start the web server
    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()  // Allow requests from any origin
            .allowed_methods(vec!["GET", "POST", "DELETE"])  // Allow GET, POST, and DELETE
            .allow_any_header()  // Allow any headers
            .max_age(3600);  // Set CORS cache time

        App::new()
            .wrap(cors)  // Add CORS middleware
            .route("/.well-known/jwks.json", web::get().to(jwks_handler))
            .route("/jwks", web::post().to(add_jwk_handler))
            .route("/jwks/{id}", web::get().to(get_jwk_by_id_handler))  // Endpoint to get a key by ID
            .route("/jwks/{id}", web::delete().to(delete_jwk_handler))  // Endpoint to delete a key
            .route("/api-docs/openapi.json", web::get().to(openapi_spec)) // Endpoint for OpenAPI specification
    })
        .bind("0.0.0.0:8080")?
        .run()
        .await
}