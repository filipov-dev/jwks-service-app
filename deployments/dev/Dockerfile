# Dev image for development
FROM rust:1.84 as dev

# Install dependencies for PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-watch for hot reload
RUN cargo install cargo-watch

RUN cargo install diesel_cli --no-default-features --features postgres

# Set the working directory
WORKDIR /app