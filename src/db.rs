//! Модуль для работы с базой данных.

use diesel::prelude::*;
use diesel::pg::PgConnection;
use dotenv::dotenv;
use std::env;

/// Устанавливает соединение с базой данных PostgreSQL.
///
/// # Пример
///
/// ```rust
/// let connection = establish_connection();
/// ```
pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}