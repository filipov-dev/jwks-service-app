# JWK Microservice

A microservice for managing JSON Web Keys (JWKs). This service provides an API for generating and storing keys used for signing and verifying JWTs (JSON Web Tokens). Keys are stored in PostgreSQL, and the service supports hot reload for development convenience.

## Features

- Generate RSA, EC, and Ed25519 keys.
- Store keys in PostgreSQL.
- Support for hot reload during development.
- API for retrieving public keys in JWK format.
- Automatic OpenAPI documentation generation.
- Interactive documentation via Swagger UI.
- Soft deletion of keys.
- Expiration of private keys and entire keys.

## Requirements

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Rust](https://www.rust-lang.org/) (optional, for local development)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/filipov-dev/jwks-service-app.git
cd jwks-service-app
```

### 2. Set Up Environment Variables

Create a `.env` file in the project root and add the following variables:

```plaintext
DATABASE_URL=postgres://user:password@db:5432/jwk_db
PRIVATE_KEY_EXPIRATION_SECONDS=86400  # 1 day (in seconds)
KEY_EXPIRATION_SECONDS=172800  # 2 days (in seconds)
```

### 3. Run the Project in Dev Mode

Navigate to the `deployments/dev` directory and start the project using Docker Compose:

```bash
cd deployments/dev
docker-compose up --build
```

This command will:
- Build the Docker image for development.
- Start containers for PostgreSQL and your application.
- The application will be available at `http://localhost:8080`.
- Swagger UI will be available at `http://localhost:8081`.

### 4. Test the API

1. Send a POST request to create a JWK:

   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"alg": "RS256"}' http://localhost:8080/jwks
   ```

2. Send a GET request to retrieve JWKs:

   ```bash
   curl http://localhost:8080/.well-known/jwks.json
   ```

3. Open Swagger UI in your browser: `http://localhost:8081`.

### 5. Stop the Project

To stop the containers, run:

```bash
docker-compose down
```

## Local Development (Without Docker)

If you prefer to develop locally, follow these steps:

1. Install Rust:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install `cargo-watch` for hot reload:

   ```bash
   cargo install cargo-watch
   ```

3. Install PostgreSQL and create a database:

   ```bash
   sudo apt-get install postgresql
   sudo -u postgres psql -c "CREATE DATABASE jwk_db;"
   sudo -u postgres psql -c "CREATE USER user WITH PASSWORD 'password';"
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE jwk_db TO user;"
   ```

4. Run the application:

   ```bash
   cargo watch -x run
   ```

## Project Structure

- `src/` — Application source code.
- `deployments/dev/` — Configuration for dev mode (Dockerfile, docker-compose.yml).
- `.env` — Environment variables file.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
