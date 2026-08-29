# Dev image for development.
#
# The base image is pinned to a patch version — it carries the cargo tools
# installed below, while the compiler the code is built with comes from
# rust-toolchain.toml (rustup switches to it inside the mounted /app). It has to
# stay close to current stable: cargo-audit below is built from source here, and
# its dependency tree already refuses anything older than rustc 1.96.
FROM rust:1.98-bookworm AS dev

# Install dependencies for PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-watch for hot reload during development
RUN cargo install cargo-watch

# Install diesel_cli with PostgreSQL support for database migrations
RUN cargo install diesel_cli --no-default-features --features postgres

# The toolchain rust-toolchain.toml selects inside the mounted /app, with the
# two components it asks for. rustup treats the `stable` alias and the exact
# version the image ships as different toolchains, so without this line every
# fresh container downloads a full toolchain on its first cargo invocation.
RUN rustup toolchain install stable --component clippy --component rustfmt

# Install cargo-audit for security vulnerability checks. --locked, as in
# .github/workflows/audit.yml: cargo-audit is built with its own lockfile, so a
# fresh release of a transitive dependency cannot break the image build.
RUN cargo install cargo-audit --locked

RUN cargo install cargo-tarpaulin

# Set the working directory inside the container
WORKDIR /app