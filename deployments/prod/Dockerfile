# Use the official Rust image as the build stage
FROM rust:1.84 as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the entire project into the container
COPY . .

# Install dependencies and build the project in release mode
RUN cargo build --release

# Use a minimal Alpine image for the final production stage
FROM alpine:latest

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/jwks-service-app ./jwks-service-app

# Expose the port the application will run on
EXPOSE 8080

# Run the application
CMD ["./jwks-service-app"]