# JWK Микросервис

Микросервис для работы с JSON Web Keys (JWK). Этот сервис предоставляет API для генерации и хранения ключей, используемых для подписи и проверки JWT (JSON Web Tokens). Ключи хранятся в PostgreSQL, а сервис поддерживает hot reload для удобства разработки.

## Возможности

- Генерация RSA, EC и Ed25519 ключей.
- Хранение ключей в PostgreSQL.
- Поддержка hot reload при разработке.
- API для получения публичных ключей в формате JWK.
- Автоматическая генерация OpenAPI-документации.
- Интерактивная документация через Swagger UI.

## Требования

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Rust](https://www.rust-lang.org/) (опционально, для локальной разработки)

## Быстрый старт

### 1. Клонирование репозитория

```bash
git clone https://github.com/filipov-dev/jwks-service-app.git
cd jwks-service-app
```

### 2. Настройка окружения

Создайте файл `.env` в корне проекта и добавьте в него следующие переменные:

```plaintext
DATABASE_URL=postgres://user:password@db:5432/jwk_db
```

### 3. Запуск проекта в dev-режиме

Перейдите в папку `deployments/dev` и запустите проект с помощью Docker Compose:

```bash
cd deployments/dev
docker-compose up --build
```

Эта команда:
- Соберет Docker-образ для разработки.
- Запустит контейнеры для PostgreSQL и вашего приложения.
- Приложение будет доступно на `http://localhost:8080`.
- Swagger UI будет доступен на `http://localhost:8081`.

### 4. Проверка работы

1. Отправьте POST-запрос для создания JWK:

   ```bash
   curl -X POST -H "Content-Type: application/json" -d '{"alg": "RS256"}' http://localhost:8080/jwks
   ```

2. Отправьте GET-запрос для получения JWK:

   ```bash
   curl http://localhost:8080/.well-known/jwks.json
   ```

3. Отправьте DELETE-запрос для удаления JWK:

   Чтобы удалить ключ (мягкое удаление), отправьте DELETE-запрос:
   
   ```bash
   curl -X DELETE http://localhost:8080/jwks/{id}
   ```
   
   Где {id} — уникальный идентификатор ключа.


4. Откройте Swagger UI в браузере: `http://localhost:8081`.

### 5. Остановка проекта

Чтобы остановить контейнеры, выполните:

```bash
docker-compose down
```

## Локальная разработка (без Docker)

Если вы предпочитаете разрабатывать проект локально, выполните следующие шаги:

1. Установите Rust:

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Установите `cargo-watch` для hot reload:

   ```bash
   cargo install cargo-watch
   ```

3. Установите PostgreSQL и создайте базу данных:

   ```bash
   sudo apt-get install postgresql
   sudo -u postgres psql -c "CREATE DATABASE jwk_db;"
   sudo -u postgres psql -c "CREATE USER user WITH PASSWORD 'password';"
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE jwk_db TO user;"
   ```

4. Запустите приложение:

   ```bash
   cargo watch -x run
   ```

## Структура проекта

- `src/` — исходный код приложения.
- `deployments/dev/` — конфигурации для dev-режима (Dockerfile, docker-compose.yml).
- `.env` — файл с переменными окружения.

## Лицензия

Этот проект распространяется под лицензией MIT. Подробнее см. в файле [LICENSE](LICENSE).
