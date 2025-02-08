use crate::models::*;
use crate::schema::jwks::dsl::*;
use actix_web::http::StatusCode;
use actix_web::{test, App};
use chrono::Utc;
use diesel::prelude::*;
use jwks_service_app::*;
use serde_json::json;

#[actix_rt::test]
async fn test_create_and_get_jwk() {
    // Start the application
    let app = test::init_service(App::new().configure(app_config)).await;

    // Create a new key
    let req = test::TestRequest::post()
        .uri("/jwks")
        .set_json(&json!({ "alg": "RS256" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Retrieve the key by ID
    let jwk: Jwk = test::read_body_json(resp).await;
    let req = test::TestRequest::get()
        .uri(&format!("/jwks/{}", jwk.id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn test_delete_jwk() {
    // Start the application
    let app = test::init_service(App::new().configure(app_config)).await;

    // Create a new key
    let req = test::TestRequest::post()
        .uri("/jwks")
        .set_json(&json!({ "alg": "RS256" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Delete the key
    let jwk: Jwk = test::read_body_json(resp).await;
    let req = test::TestRequest::delete()
        .uri(&format!("/jwks/{}", jwk.id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Attempt to retrieve the deleted key
    let req = test::TestRequest::get()
        .uri(&format!("/jwks/{}", jwk.id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_expired_jwk() {
    // Start the application
    let app = test::init_service(App::new().configure(app_config)).await;

    // Create a new key
    let req = test::TestRequest::post()
        .uri("/jwks")
        .set_json(&json!({ "alg": "RS256" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Retrieve the key by ID
    let jwk: Jwk = test::read_body_json(resp).await;

    // Set the private key expiration time to the past
    let connection = &mut db::establish_connection();
    diesel::update(jwks.filter(id.eq(jwk.id)))
        .set(private_key_expires_at.eq(Some(Utc::now().naive_utc() - chrono::Duration::days(1))))
        .execute(connection)
        .expect("Failed to update key");

    // Attempt to retrieve the key with an expired private key
    let req = test::TestRequest::get()
        .uri(&format!("/jwks/{}", jwk.id))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::GONE);
}