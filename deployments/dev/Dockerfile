# Dev-образ для разработки
FROM rust:1.84 as dev

# Устанавливаем зависимости для работы с PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Устанавливаем cargo-watch для hot reload
RUN cargo install cargo-watch

# Создаем рабочую директорию
WORKDIR /app