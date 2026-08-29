//! Shared harness for the tests that touch the database.
//!
//! The tests drive the real handlers, and a handler opens its own connection
//! from `DATABASE_URL` every time it runs. Nothing the test holds is therefore
//! visible to the code under test: it cannot wrap the work in a transaction and
//! roll it back, and it cannot hide behind a connection-scoped `search_path`
//! either. Isolation is built out of the two things that are left — the
//! database tests run one at a time, and each one removes what appeared while
//! it was running.

use chrono::{NaiveDateTime, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel_migrations::MigrationHarness;
use jwks_service_app::schema::jwks::dsl::{created_at, jwks};
use jwks_service_app::{db, MIGRATIONS};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Held by whichever test is currently allowed to touch the database.
static DB_LOCK: Mutex<()> = Mutex::new(());

/// Migrations are applied by the first test that gets the lock; the rest find
/// the schema already in place.
static MIGRATED: OnceLock<()> = OnceLock::new();

/// Exclusive access to the database for the duration of one test.
///
/// Obtained with [`TestDatabase::lock`] and released — together with the rows
/// the test produced — when the value goes out of scope.
pub struct TestDatabase {
    /// While this guard is alive no other database test runs, which is what
    /// makes the time window below belong to this test alone.
    _guard: MutexGuard<'static, ()>,
    connection: PgConnection,
    /// Anything written from this moment on is this test's own leftovers.
    opened_at: NaiveDateTime,
}

impl TestDatabase {
    /// Waits for the other database tests to finish, brings the schema up to
    /// date and hands back a connection of its own.
    pub fn lock() -> Self {
        // A test that fails while holding the lock poisons it, but it leaves
        // nothing behind — the cleanup below runs while unwinding. The poison
        // flag carries no information here, and honouring it would turn one red
        // test into a cascade of unrelated ones.
        let guard = DB_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut connection = db::establish_connection();

        // The suite applies the migrations itself rather than expecting someone
        // to have run `diesel migration run` first: CI then needs neither the
        // diesel CLI nor a step of its own, and a local run works against any
        // empty database.
        MIGRATED.get_or_init(|| {
            connection
                .run_pending_migrations(MIGRATIONS)
                .expect("failed to apply the migrations");
        });

        Self {
            _guard: guard,
            connection,
            opened_at: Utc::now().naive_utc(),
        }
    }

    /// A connection for the setup and the assertions a test cannot express
    /// through the HTTP endpoints.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.connection
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        // A hard delete on purpose: the endpoint only marks a key as deleted,
        // so every row a test ever created outlives it and the next run starts
        // from a database that keeps growing. The rows are matched by the time
        // window instead of by collected identifiers — a test cannot forget to
        // register a key it never saw, and the lock guarantees no one else
        // wrote inside the window.
        let removed = diesel::delete(jwks.filter(created_at.ge(self.opened_at)))
            .execute(&mut self.connection);

        if let Err(error) = removed {
            let message = format!("failed to remove the rows the test created: {error}");

            if std::thread::panicking() {
                // Panicking inside a drop that runs while the thread is already
                // unwinding aborts the process and buries the failure that
                // started it.
                eprintln!("{message}");
            } else {
                panic!("{message}");
            }
        }
    }
}
