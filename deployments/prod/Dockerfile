# Use the official Rust image as the build stage
FROM rust:1.84 as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Install dependencies for PostgreSQL
RUN apk add --no-cache musl-dev openssl-dev postgresql-dev

# Copy the entire project into the container
COPY . .

# Install dependencies and build the project in release mode
RUN cargo build --release

# Use a minimal Alpine image for the final production stage
FROM alpine:latest

# Install dependencies for Runtime
RUN apk add --no-cache libgcc openssl postgresql-libs

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/jwks-service-app ./jwks-service-app

ENV RUN_MIGRATIONS_ON_START 1

# Expose the port the application will run on
EXPOSE 8080

# Run the application
CMD ["/usr/src/app/target/release/jwks-service-app"]