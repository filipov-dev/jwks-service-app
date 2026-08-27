# AGENTS.md

Rules that govern this repository: conventions, invariants and release
mechanics. What the service is and how to run it — [`README.md`](README.md);
what the API looks like — the OpenAPI spec and the `utoipa` annotations next to
the handlers. Nothing of that is repeated here.

> Private notes (accesses, tracker flow, owner preferences) live in
> `AGENTS_INTERNAL.md`. That file is listed in `.gitignore` and is never
> committed.

The service exists to make key and certificate management convenient:
generation, storage, lifecycle and publication of JWKs. It is general-purpose —
never let the needs of one particular consumer become the contract.

## Repository rules

- **A change that adds functionality also writes its own section of this
  document.** A new rule of thumb goes into conventions, a new release
  constraint into versioning. This rule lives here instead of being repeated in
  thirty tickets, and it is the only thing that keeps the document from rotting
  within two phases.
- **Module boundaries:** HTTP in `handlers.rs`, key generation in `crypto.rs`,
  persistence in `db.rs`/`schema.rs`, request and response shapes in
  `models.rs`, routes and `ApiDoc` in `lib.rs`.
- **No secrets in the repository.** CI credentials live in GitHub Secrets.
- **What gates a change:** CI runs `cargo clippy -- -D warnings`, `cargo test`
  with coverage, and `cargo audit`. The test suite is not hermetic — it needs
  `DATABASE_URL` pointing at a database with the migrations applied.

## Conventions

- **`unwrap`/`expect` only in `main.rs`, and only at startup**, as fail-fast on
  configuration. Domain and HTTP code returns `Result` and propagates with `?`.
  The `.expect()` calls still sitting in `handlers.rs` and `db.rs` are legacy
  and are being removed — do not copy the pattern.
- **Fail-fast applies to access secrets only.** Anything that cannot serve a
  request without it — database, master key, auth credentials — stops the
  process at startup. Telemetry and limits degrade instead: missing tracing,
  metrics or rate-limit configuration logs a warning and the service keeps
  running.
- **Log levels are chosen by who is at fault, not by how alarming the text
  looks.** A client sending a bad `alg` is `DEBUG`; a failing dependency is
  `ERROR`; a degraded optional subsystem is `WARN`.
- **Headers and bodies are never logged.** Requests carry key material and
  responses contain private keys; no redaction rule survives contact with a new
  field, so the rule is a blanket one.
- **Errors leave the service sparse:** a status and a short structured body, no
  internal cause, no SQL, no key material. Details belong in the log.
- **A new endpoint gets `deny_cors`, a `utoipa::path` annotation and
  registration in `ApiDoc`** (`lib.rs`), together with any new schema.
  Permissive CORS is granted per endpoint and only where a browser needs it; an
  endpoint missing from `ApiDoc` does not exist for consumers.
- **Public output is built by projecting `JwkData` onto `Jwk`.** Never serialize
  a row straight into a response — the separation of the two structs is what
  keeps private material out of public endpoints by construction.
- **A new environment variable is added in four places at once:**
  `.env.example`, `deployments/dev/docker-compose.yml`,
  `deployments/prod/README.md` (it is published as the Docker Hub description)
  and the code that reads it.
- **This repository is English.** Code, comments, `utoipa` descriptions,
  documentation, commit messages (conventional commits — they end up in the
  release body), PR titles and bodies. No exceptions, and no mixed languages
  inside a file.
- **Every migration ships a working `down.sql`.** Rolling the image back does
  not roll the schema back, so a migration without a tested revert turns a
  five-minute rollback into an incident. Verify with `diesel migration revert`.

## Versioning and releases

- **Every commit bumps the version in `Cargo.toml`. Without exception** — a
  documentation fix, a CI tweak and a dependency bump each get their own patch
  release. There is no "no-version" change in this repository.
- **The digit is chosen by the nature of the change**, per semver:
  - **major** — compatibility is broken: a removed or renamed endpoint, a
    changed status or response shape, a changed key format or storage format, a
    configuration variable that becomes required or changes meaning;
  - **minor** — backward-compatible functionality: a new endpoint, a new
    optional field, a new environment variable with a default;
  - **patch** — everything else: fixes, refactoring, documentation, CI,
    dependency updates.
- **The version is the release trigger, not metadata.** A push to `master` that
  touches `Cargo.toml` runs `release.yml`: it cuts a GitHub Release tagged
  `v<version>` and dispatches `docker.yml`, which publishes the multi-arch image
  as `<version>` and `latest` to both Docker Hub and GHCR. Treat every version
  edit as a publication.
- **A version is never reused and never walked back.** The tag `v<version>` and
  the image tag already exist; re-releasing the same number silently moves
  `latest` onto different bits. Roll forward with a new patch instead.
- **`Cargo.lock` is committed together with `Cargo.toml`** — the lockfile
  carries the crate's own version, so a bump that leaves it behind makes the
  next build dirty.
- **Keep `version` the first `version =` line in `Cargo.toml`.** The release and
  image workflows read it with `grep -m1 'version' Cargo.toml`; a dependency
  line above it would tag the release with a dependency's version.
- **Release images are built on native runners per platform.** Under QEMU
  emulation `cc`/`collect2` segfaults while linking the aarch64 build scripts —
  that is what broke the 2.0.0 image.
