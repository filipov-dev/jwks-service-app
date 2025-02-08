//! This module contains the main application logic for the JWK microservice.

use actix_cors::Cors;
use actix_web::*;
use diesel_migrations::MigrationHarness;
use dotenv::dotenv;
use jwks_service_app::{app_config, MIGRATIONS};
use std::env;

mod db;
mod schema;

#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Check if migrations need to be run
    if env::var("RUN_MIGRATIONS_ON_START").unwrap_or_default() == "1" {
        let connection = &mut db::establish_connection();
        println!("Running migrations...");

        // Run migrations
        connection
            .run_pending_migrations(MIGRATIONS)
            .expect("Failed to run migrations");

        // Get the list of applied migrations
        let applied_migrations = connection
            .applied_migrations()
            .expect("Failed to get applied migrations");
        println!("Applied migrations:");
        for migration in applied_migrations {
            println!("- {}", migration);
        }

        println!("Migrations completed.");
    }

    // Start the web server
    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin() // Allow requests from any origin
            .allowed_methods(vec!["GET", "POST", "DELETE"]) // Allow GET, POST, and DELETE
            .allow_any_header() // Allow any headers
            .max_age(3600); // Set CORS cache time

        App::new().wrap(cors).configure(app_config)
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
