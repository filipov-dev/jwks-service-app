# JWK Manager

A lightweight application for managing JSON Web Keys (JWKs) with built-in support for database migrations and key expiration.

---

## Features

- **Database Integration**: Connects to a PostgreSQL database for storing keys and metadata.
- **Automatic Migrations**: Optionally runs database migrations on application startup.
- **Key Expiration**: Configurable expiration times for private keys and JWKs.
- **Dockerized**: Easy to deploy using Docker.

---

## Environment Variables

The following environment variables are required to configure the application:

| Variable Name                     | Description                                                                 | Default Value           |
|-----------------------------------|-----------------------------------------------------------------------------|-------------------------|
| `DATABASE_URL`                    | PostgreSQL connection URL (e.g., `postgres://user:password@db:5432/jwk_db`) | **Required**            |
| `RUN_MIGRATIONS_ON_START`         | Run database migrations on application start (`1` = true, `0` = false)      | `1`                     |
| `PRIVATE_KEY_EXPIRATION_SECONDS`  | Expiration time for private keys in seconds                                | `86400` (1 day)         |
| `KEY_EXPIRATION_SECONDS`          | Expiration time for JWKs in seconds                                        | `172800` (2 days)       |
| `HOST`                            | Address the service binds to. Set to `0.0.0.0` to accept traffic from outside the container | `127.0.0.1`             |
| `PORT`                            | Port the service listens on (1-65535)                                      | `8080`                  |

---

## Quick Start

1. **Pull the Docker Image**:
   ```bash
   docker pull filipov/jwks-service-app:latest
   ```

2. **Run the Container**:
   Replace the placeholders with your actual database credentials and configuration.
   ```bash
   docker run -d \
     --name jwks-service-app \
     -e DATABASE_URL=postgres://user:password@db:5432/jwk_db \
     -e RUN_MIGRATIONS_ON_START=1 \
     -e PRIVATE_KEY_EXPIRATION_SECONDS=86400 \
     -e KEY_EXPIRATION_SECONDS=172800 \
     -e HOST=0.0.0.0 \
     -p 8080:8080 \
     filipov/jwks-service-app:latest
   ```

   `HOST=0.0.0.0` is required: the service binds to `127.0.0.1` by default, which inside a
   container means nothing outside can reach it.

3. **Verify the Application**:
   Check the logs to ensure the application started successfully:
   ```bash
   docker logs jwks-service-app
   ```

---

## Database Migrations

If `RUN_MIGRATIONS_ON_START` is set to `1`, the application will automatically apply database migrations on startup. Ensure your database is accessible and properly configured.

---

## Key Expiration

- **Private Keys**: Expire after `PRIVATE_KEY_EXPIRATION_SECONDS` (default: 1 day).
- **JWKs**: Expire after `KEY_EXPIRATION_SECONDS` (default: 2 days).

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on the [GitHub repository](https://github.com/filipov-dev/jwks-service-app.git).

---

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/filipov-dev/jwks-service-app/blob/master/LICENSE) file for details.

---
