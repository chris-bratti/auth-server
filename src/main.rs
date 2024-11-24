use actix_web::cookie::Key;
use auth_server::{
    auth::{self, AuthError, LoginCredentials, NewUserData},
    server::helpers::get_env_variable,
    AuthRequest, AuthType, ChangePasswordRequest, LoginRequest, SignupRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

use actix_web::*;

use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Generate the list of routes in your Leptos App

    let secret_key = get_secret_key();
    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(
                IdentityMiddleware::builder()
                    .login_deadline(Some(Duration::new(259200, 0)))
                    .build(),
            )
            .wrap(
                SessionMiddleware::builder(store.clone(), secret_key.clone())
                    .cookie_secure(false)
                    .session_lifecycle(
                        PersistentSession::default()
                            .session_ttl(actix_web::cookie::time::Duration::weeks(2)),
                    )
                    .build(),
            )
            .service(auth::logout)
            .service(auth::get_user_from_session)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

fn get_secret_key() -> Key {
    return Key::generate();
}

#[post("/auth_request")]
async fn auth_request(
    auth_payload: web::Json<AuthRequest>,
    request: HttpRequest,
) -> Result<HttpResponse, AuthError> {
    let request_type = request
        .headers()
        .get("X-Request-Type")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest)?;

    let AuthRequest { username, data } = auth_payload.into_inner();

    match AuthType::from(request_type) {
        AuthType::Login => {
            let data: LoginRequest =
                serde_json::from_value(data).map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_login(username, data, request).await?;
        }
        AuthType::Signup => {
            let data: SignupRequest =
                serde_json::from_value(data).map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_signup(username, data, request).await?;
        }
        AuthType::ChangePassword => {
            let data: ChangePasswordRequest =
                serde_json::from_value(data).map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_change_password(username, data).await?;
        }
        _ => return Err(AuthError::InvalidRequest),
    }

    Ok(HttpResponse::Ok().finish())
}
