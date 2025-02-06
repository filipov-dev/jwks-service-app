//! This module provides functionality for establishing a connection to the database.

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;

/// Establishes a connection to the PostgreSQL database.
///
/// # Returns
///
/// A `PgConnection` instance representing the database connection.
///
/// # Panics
///
/// This function will panic if the `DATABASE_URL` environment variable is not set
/// or if the connection to the database fails.
pub fn establish_connection() -> PgConnection {
    // Load environment variables from the `.env` file (if it exists).
    dotenv().ok();

    // Retrieve the database URL from the environment variables.
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in the environment variables or .env file");

    // Establish a connection to the database.
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}