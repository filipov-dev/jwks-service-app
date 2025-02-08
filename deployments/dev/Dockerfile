# Dev image for development
FROM rust:1.84 as dev

# Install dependencies for PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-watch for hot reload during development
RUN cargo install cargo-watch

# Install diesel_cli with PostgreSQL support for database migrations
RUN cargo install diesel_cli --no-default-features --features postgres

# Add Rust tools for linting and formatting
RUN rustup component add clippy
RUN rustup component add rustfmt

# Install cargo-audit for security vulnerability checks
RUN cargo install cargo-audit

RUN cargo install cargo-tarpaulin

# Set the working directory inside the container
WORKDIR /app