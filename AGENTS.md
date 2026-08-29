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
- **What gates a change: one workflow, `.github/workflows/ci.yml`.** It runs
  `cargo fmt --all -- --check`, then `cargo clippy --all-targets -- -D
  warnings`, then the build, the tests and coverage — in that order, on every
  pull request and on every push to `master`. Formatting comes first because it
  is the only step that compiles nothing, so an unformatted tree costs seconds
  instead of a build; `--all-targets` is what puts the test code under the same
  lints as the crate. `master` is in the triggers on purpose: with the checks
  running on pull requests only, it was the one branch whose code was last
  verified somewhere else. `cargo audit` keeps its own workflow — it also runs
  on a schedule, and an advisory published overnight is not a reason to fail an
  unrelated pull request.
- **A test that touches the database goes through `tests/common`.** Handlers
  open their own connection from `DATABASE_URL` on every call, so a test cannot
  wrap its work in a transaction and roll it back — nothing it holds is visible
  to the code under test. `TestDatabase::lock()` serializes the database tests
  instead and, when the test ends, deletes every row that appeared while it held
  the lock; a hard delete, because the endpoint only marks a key as deleted. It
  applies the migrations itself, which is why CI needs neither the diesel CLI
  nor a schema step. The suite is still not hermetic — it needs `DATABASE_URL`
  pointing at a database it may write to.
- **The toolchain comes from `rust-toolchain.toml`** — the moving `stable`
  channel with `clippy` and `rustfmt`, the same channel CI installs. Without it
  the local compiler is whatever the developer installed last, lints that
  appeared in a newer stable are invisible until the pipeline fails on them.
  The release image is the one exception: it pins an exact version through
  `RUSTUP_TOOLCHAIN`, which takes precedence over this file.
- **The Docker build context is an allowlist in `.dockerignore`:** everything
  is ignored and only what the release build reads — `Cargo.toml`,
  `Cargo.lock`, `src/`, `migrations/` — is let back in. A denylist leaks by
  default, and `COPY . .` would otherwise carry `target/` and a local `.env`
  into the image. **A new build input is added there in the same change that
  introduces it**, otherwise the build fails inside the container on a file
  that exists in the tree.
- **Container images are pinned to an exact version, never to `:latest` or to a
  floating major.** That covers the base images of both Dockerfiles, the
  database of the dev stand, the service container of the test workflow and the
  `docker run` examples in `README.md` and `deployments/prod/README.md`.
  Versioning protects pinned consumers only, and an unpinned one takes the next
  major silently on its next pull. The pins are kept current by the `docker`
  and `docker-compose` entries in `.github/dependabot.yml`; the example tag in
  the two READMEs is not release metadata and is raised only when a major
  release makes it misleading.
- **Dependency, action and image updates arrive weekly from
  `.github/dependabot.yml`** (the `cargo`, `github-actions`, `docker` and
  `docker-compose` ecosystems). The commit prefixes are set there to `deps` and
  `ci` so that the updates are filed by `scripts/changelog.sh` under "Internal"
  instead of "Other".
- **An advisory is silenced only in `.cargo/audit.toml`, with a reason and a
  revisit date.** cargo-audit reads that path relative to the working directory
  — a file at the repository root is picked up by nothing, and a `--ignore`
  flag in the workflow hides the reason from everyone reading the tree. The
  entry is for advisories this repository cannot act on: a vulnerable version
  reached only through a dependency that has no fixed release. Anything
  `cargo update` can move is updated instead of ignored.

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
- **A dependabot pull request is not exempt from the version bump.** It arrives
  with `Cargo.toml` and `Cargo.lock` changed and the version untouched, so
  merging it as is publishes nothing and leaves the next change to carry
  someone else's dependency update into its release. Add the patch bump and the
  `CHANGELOG.md` section on the dependabot branch before merging.
- **`Cargo.lock` is committed together with `Cargo.toml`** — the lockfile
  carries the crate's own version, so a bump that leaves it behind makes the
  next build dirty.
- **Keep `version` the first line of `Cargo.toml` that starts with `version`.**
  The release and image workflows read it with `grep -m1 '^version' Cargo.toml`;
  a dependency table written in the long form (`[dependencies.foo]` followed by
  its own `version =`) placed above it would tag the release with a
  dependency's version.
- **Release notes and `CHANGELOG.md` are generated from commit subjects by
  `scripts/changelog.sh`.** `release.yml` runs it with no arguments to build the
  body of the GitHub Release; `--all` regenerates the whole file. The subject
  line *is* the changelog entry, so write it to be read on its own:
  `type(scope): what changed (JWKSAPP-N)`. Anything that does not parse as a
  conventional commit lands in "Other"; the mapping of types onto sections is
  `bucket_for` in the script, and a new type is added there.
- **The section of a new version is written into `CHANGELOG.md` in the same
  change that bumps the version** — `scripts/changelog.sh --insert`. The tag is
  cut only after the merge, so regenerating with `--all` at that moment would
  file the change under "Unreleased" instead of under its number.
- **Release images are built on native runners per platform.** Under QEMU
  emulation `cc`/`collect2` segfaults while linking the aarch64 build scripts —
  that is what broke the 2.0.0 image.
