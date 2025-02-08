# Этап сборки
FROM rust:1.84-alpine as builder

# Устанавливаем необходимые зависимости для сборки
RUN apk add --no-cache musl-dev openssl-dev postgresql-dev

# Устанавливаем target для статической компиляции с использованием musl
RUN rustup target add x86_64-unknown-linux-musl

# Создаем рабочую директорию
WORKDIR /app

# Копируем файлы проекта
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

# Собираем зависимости (кэшируем их)
RUN mkdir -p ./src && echo "fn main() {}" > ./src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
RUN rm -rf ./src

# Копируем исходный код и собираем проект
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

# Финальный этап: используем последнюю версию Alpine Linux
FROM alpine:3.18

# Устанавливаем runtime-зависимости
RUN apk add --no-cache libgcc openssl postgresql-libs

# Копируем собранное приложение из этапа сборки
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/jwks-service-app /usr/local/bin/jwks-service-app

# Копируем миграции
COPY --from=builder /app/migrations /app/migrations

# Указываем рабочую директорию
WORKDIR /app

# Указываем переменные окружения для Diesel
ENV DATABASE_URL=postgres://user:password@db:5432/jwks_service
ENV RUST_LOG=info

# Указываем точку входа
ENTRYPOINT ["/usr/local/bin/jwks-service-app"]