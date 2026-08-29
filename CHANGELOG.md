# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

This file is built from the commit history and is regenerated with
`scripts/changelog.sh --all`; the body of every GitHub Release is built by the
same script. The entries are commit subjects verbatim, with the tracker issue
key in parentheses.

Two sections are added to the six of Keep a Changelog: "Documentation" (client
examples and operations instructions — changes for the consumer of the service)
and "Internal" (CI, tests, formatting).

## [2.0.14] - 2026-08-29

### Internal

- bump base64 from 0.22.1 to 0.23.1
- release 2.0.14

## [2.0.13] - 2026-08-29

### Internal

- bump sha1 from 0.10.7 to 0.11.0
- release 2.0.12
- renumber the release to 2.0.13, taken by JWKSAPP-38

## [2.0.12] - 2026-08-29

### Internal

- gate master through one pipeline and isolate the database tests (JWKSAPP-38)

## [2.0.11] - 2026-08-29

### Internal

- bump utoipa from 3.5.0 to 5.5.0
- release 2.0.11 with the spec emitted as OpenAPI 3.1

## [2.0.10] - 2026-08-29

### Internal

- bump rust in /deployments/prod
- move the pinned release toolchain to 1.98.0 with the base image

## [2.0.9] - 2026-08-29

### Internal

- bump postgres from 13.23 to 18.6 in /deployments/dev
- follow the dev stand to postgres 18.6 in the test workflow

## [2.0.8] - 2026-08-29

### Internal

- bump actions/download-artifact from 4 to 8
- release 2.0.8

## [2.0.7] - 2026-08-29

### Internal

- bump actions/upload-artifact from 4 to 7
- release 2.0.7

## [2.0.6] - 2026-08-29

### Internal

- bump docker/login-action from 4.5.2 to 4.6.0
- release 2.0.6

## [2.0.5] - 2026-08-28

### Internal

- pin the toolchain and every container image (JWKSAPP-10)

## [2.0.4] - 2026-08-27

### Security

- **deps**: close the open cargo audit advisories (JWKSAPP-42)

### Internal

- add a dependabot config and refresh the workflow actions (JWKSAPP-42)

### Other

- Bump bytes from 1.10.0 to 1.11.1
- Bump actix-http from 3.9.0 to 3.12.1
- Bump openssl from 0.10.70 to 0.10.80
- Bump tokio from 1.43.0 to 1.46.1

## [2.0.2] - 2026-08-27

### Internal

- build release notes and CHANGELOG.md from conventional commits (JWKSAPP-9)

## [2.0.1] - 2026-08-27

### Documentation

- agent instructions — AGENTS.md, CLAUDE.md, gitignore entry (JWKSAPP-41)

## [2.0.0] - 2026-08-25

### Other

- Bump ring from 0.17.8 to 0.17.13
- JWKSAPP-8: Configure bind address from environment
- JWKSAPP-8: Build release images on native runners

## [1.1.0] - 2025-02-22

### Other

- JWKSAPP-8: Set binding from env
- JWKSAPP-8: Set binding from env

## [1.0.12] - 2025-02-22

### Other

- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly
- Implement the JWKS Standard correctly

## [1.0.0] - 2025-02-22

### Other

- Create CODE_OF_CONDUCT.md
- Update issue templates
- Create SECURITY.md
- Create CONTRIBUTING.md
- JWKSAPP-7: Implement the JWKS Standard correctly

## [0.1.0] - 2025-02-09

### Other

- Simple RSA key storage
- JWKSAPP-1: Generate a new key
- JWKSAPP-2: Use multiple algorithms to generate keys
- JWKSAPP-3: Add additional information and development tools
- JWKSAPP-4: Add keys lifecycle
- JWKSAPP-5: Update docs
- JWKSAPP-6: Add checks and automation
- JWKSAPP-6: Add checks and automation
- JWKSAPP-6: Add checks and automation
- JWKSAPP-6: Add checks and automation
- JWKSAPP-6: Add checks and automation
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.
- - Generate RSA, EC, and Ed25519 keys. - Store keys in PostgreSQL. - API for retrieving public keys in JWK format. - Automatic OpenAPI documentation generation. - Interactive documentation via Swagger UI. - Soft deletion of keys. - Expiration of private keys and entire keys.

[Unreleased]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.14...HEAD
[2.0.14]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.13...v2.0.14
[2.0.12]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.11...v2.0.12
[2.0.11]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.10...v2.0.11
[2.0.10]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.9...v2.0.10
[2.0.9]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.8...v2.0.9
[2.0.8]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.7...v2.0.8
[2.0.7]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.6...v2.0.7
[2.0.6]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.5...v2.0.6
[2.0.5]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.4...v2.0.5
[2.0.4]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.2...v2.0.4
[2.0.2]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/filipov-dev/jwks-service-app/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/filipov-dev/jwks-service-app/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/filipov-dev/jwks-service-app/compare/v1.0.12...v1.1.0
[1.0.12]: https://github.com/filipov-dev/jwks-service-app/compare/v1.0.0...v1.0.12
[1.0.0]: https://github.com/filipov-dev/jwks-service-app/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/filipov-dev/jwks-service-app/releases/tag/v0.1.0
