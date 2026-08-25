# Multi-stage build with cargo-chef: dependencies are compiled in a separate
# layer that is invalidated only when Cargo.toml/Cargo.lock change. A source
# edit no longer rebuilds openssl/actix-web from scratch — the dependency layer
# is reused (in CI through the GHA cache, see .github/workflows/docker.yml).
#
# Rust 1.90 slim-bookworm: bookworm is needed to link against the same libssl3
# as the runner stage.
FROM rust:1.90-slim-bookworm AS chef

# Pin the toolchain inside the image so the released binary is built by a known
# compiler: without it cargo would pull the latest stable, and `cargo chef cook`
# (which runs before the sources are copied) could use a different compiler than
# the later `cargo build`, invalidating the dependency layer on every run.
ENV RUSTUP_TOOLCHAIN=1.90.0

# openssl-sys needs pkg-config and the libssl headers at build time; libpq is
# required by diesel's postgres backend.
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
      pkg-config \
      libssl-dev \
      libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# cargo-chef is installed once in the base layer and reused by both the planner
# and the builder stage.
RUN cargo install cargo-chef --locked --version 0.1.77

WORKDIR /app

# Planner stage: turn the full source tree into a "recipe" — the dependency list
# without the code itself. The recipe changes only when dependencies change.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Builder stage: first build ONLY the dependencies from the recipe (cacheable
# layer), then copy the sources and build the crate itself.
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Compiling dependencies is the heaviest step; it stays cached until
# recipe.json (i.e. Cargo.toml/Cargo.lock) changes.
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Final stage: Debian Slim (bookworm — same OpenSSL 3 as the builder).
FROM debian:bookworm-slim AS runner

# Install runtime dependencies
RUN apt-get update --fix-missing && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        libpq5 \
        ca-certificates \
        && rm -rf /var/lib/apt/lists/*

# Copy the built application from the builder stage
COPY --from=builder /app/target/release/jwks-service-app /usr/local/bin/jwks-service-app

# Set the working directory
WORKDIR /app

# Set the entry point
ENTRYPOINT ["/usr/local/bin/jwks-service-app"]
