use dotenv::dotenv;
use std::env;
use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use diesel::prelude::*;
use openssl::nid::Nid;
use uuid::Uuid;
use crate::crypto::{generate_ec_keypair, generate_ed25519_keypair, generate_rsa_keypair};
use crate::db::establish_connection;
use crate::models::{AlgorithmInput, Jwk, Jwks};
use crate::schema::jwks::dsl::*;

/// Обработчик для получения JWK.
///
/// # Возвращает
///
/// Возвращает JSON с набором JWK.
///
/// # Пример
///
/// ```bash
/// curl http://localhost:8080/.well-known/jwks.json
/// ```
#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    responses(
        (status = 200, description = "Список JWK", body = Jwks)
    )
)]
pub async fn jwks_handler() -> impl Responder {
    let connection = &mut establish_connection();

    // Возвращаем только активные ключи (deleted_at IS NULL и key_expires_at > NOW)
    let results = jwks
        .filter(deleted_at.is_null())
        .filter(key_expires_at.gt(Utc::now().naive_utc()))
        .load::<Jwk>(connection)
        .expect("Error loading jwks");

    // Убираем приватный ключ из ответа
    let public_jwks = results.into_iter().map(|jwk| Jwk {
        id: jwk.id,
        kty: jwk.kty,
        alg: jwk.alg,
        kid: jwk.kid,
        n: jwk.n,
        e: jwk.e,
        d: "".to_string(), // Приватный ключ не возвращаем
        created_at: jwk.created_at,
        deleted_at: None,
        private_key_expires_at: None,
        key_expires_at: None,
    }).collect::<Vec<_>>();

    let jwks_list = Jwks {
        keys: public_jwks,
    };

    HttpResponse::Ok().json(jwks_list)
}

/// Обработчик для генерации JWK.
///
/// # Аргументы
///
/// * `input` - Входные данные с названием алгоритма.
///
/// # Возвращает
///
/// Возвращает статус `201 Created`, если ключ успешно сгенерирован и сохранен.
///
/// # Пример
///
/// ```bash
/// curl -X POST -H "Content-Type: application/json" -d '{"alg": "RS256"}' http://localhost:8080/jwks
/// ```
#[utoipa::path(
    post,
    path = "/jwks",
    request_body = AlgorithmInput,
    responses(
        (status = 201, description = "JWK успешно добавлен", body = Jwk)
    )
)]
pub async fn add_jwk_handler(input: web::Json<AlgorithmInput>) -> impl Responder {
    dotenv().ok();

    let algorithm = &input.alg;

    // Получаем время протухания из переменных окружения
    let private_key_expiration_seconds: i64 = env::var("PRIVATE_KEY_EXPIRATION_SECONDS")
        .unwrap_or_else(|_| "86400".to_string())  // По умолчанию 1 день
        .parse()
        .expect("PRIVATE_KEY_EXPIRATION_SECONDS must be a number");

    let key_expiration_seconds: i64 = env::var("KEY_EXPIRATION_SECONDS")
        .unwrap_or_else(|_| "172800".to_string())  // По умолчанию 2 дня
        .parse()
        .expect("KEY_EXPIRATION_SECONDS must be a number");

    // Генерация ключей в зависимости от алгоритма
    let (public_key, private_key) = match algorithm.as_str() {
        "RS256" | "RS384" | "RS512" => generate_rsa_keypair(2048),
        "ES256" => generate_ec_keypair(Nid::X9_62_PRIME256V1),
        "ES384" => generate_ec_keypair(Nid::SECP384R1),
        "ES512" => generate_ec_keypair(Nid::SECP521R1),
        "Ed25519" => generate_ed25519_keypair(),
        _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
    };

    // Текущее время
    let now = Utc::now().naive_utc();

    // Создание JWK
    let jwk = Jwk {
        id: Uuid::new_v4(),
        kty: match algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => "RSA".to_string(),
            "ES256" | "ES384" | "ES512" => "EC".to_string(),
            "Ed25519" => "OKP".to_string(), // Octet Key Pair (Ed25519)
            _ => return HttpResponse::BadRequest().body("Unsupported algorithm"),
        },
        alg: algorithm.clone(),
        kid: Uuid::new_v4().to_string(), // Уникальный идентификатор ключа
        n: public_key, // Модуль ключа (публичный ключ)
        e: match algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => "AQAB".to_string(), // Публичная экспонента для RSA
            _ => "".to_string(), // Для EC и Ed25519 это поле не используется
        },
        d: private_key, // Приватный ключ
        created_at: Utc::now().naive_utc(),
        deleted_at: None,
        private_key_expires_at: Some(now + chrono::Duration::seconds(private_key_expiration_seconds)),
        key_expires_at: Some(now + chrono::Duration::seconds(private_key_expiration_seconds + key_expiration_seconds)),
    };

    // Сохранение JWK в базу данных
    let connection = &mut establish_connection();
    diesel::insert_into(jwks)
        .values(&jwk)
        .execute(connection)
        .expect("Error saving new jwk");

    HttpResponse::Created().json(jwk)
}

/// Получить JWK по ID (включая приватную часть)
#[utoipa::path(
    get,
    path = "/jwks/{id}",
    params(
        ("id" = String, Path, description = "Уникальный идентификатор ключа")
    ),
    responses(
        (status = 200, description = "Ключ найден", body = models::Jwk),
        (status = 404, description = "Ключ не найден"),
        (status = 410, description = "Приватный ключ протух")
    )
)]
pub async fn get_jwk_by_id_handler(key_id: web::Path<Uuid>) -> impl Responder {
    let connection = &mut establish_connection();

    // Ищем ключ по ID
    let result = jwks
        .filter(id.eq(key_id.into_inner()))
        .filter(deleted_at.is_null())  // Исключаем удалённые ключи
        .filter(key_expires_at.gt(Utc::now().naive_utc()))  // Исключаем протухшие ключи
        .first::<Jwk>(connection);

    match result {
        Ok(jwk_result) => {
            // Проверяем, не протух ли приватный ключ
            let now = Utc::now().naive_utc();
            if let Some(expires_at) = jwk_result.private_key_expires_at {
                if now > expires_at {
                    return HttpResponse::Gone().body("Private key expired");
                }
            }

            HttpResponse::Ok().json(jwk_result)
        }
        Err(_) => HttpResponse::NotFound().body("Key not found"),
    }
}

/// Удалить JWK (мягкое удаление)
#[utoipa::path(
    delete,
    path = "/jwks/{id}",
    params(
        ("id" = String, Path, description = "Уникальный идентификатор ключа")
    ),
    responses(
        (status = 204, description = "Ключ успешно удалён"),
        (status = 404, description = "Ключ не найден")
    )
)]
pub async fn delete_jwk_handler(key_id: web::Path<Uuid>) -> impl Responder {
    let connection = &mut establish_connection();

    // Устанавливаем deleted_at в текущую дату и время
    let result = diesel::update(jwks.filter(id.eq(key_id.into_inner())))
        .set(deleted_at.eq(Some(Utc::now().naive_utc())))
        .execute(connection);

    match result {
        Ok(0) => HttpResponse::NotFound().body("Key not found"),
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(_) => HttpResponse::InternalServerError().body("Failed to delete key"),
    }
}