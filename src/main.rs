use actix_web::cookie::Key;
use auth_server::{
    auth::{self},
    server::auth_functions::get_env_variable,
    AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest, LoginRequest,
    ResetPasswordRequest, SignupRequest, VerifyOtpRequest, VerifyUserRequest,
};
use std::time::Duration;

use actix_web::*;

use actix_identity::IdentityMiddleware;
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

    println!("Starting server on port 8080");

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
            .service(auth_request)
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}

fn get_secret_key() -> Key {
    return Key::generate();
}

#[post("/auth")]
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

    let response = match AuthType::from(request_type) {
        AuthType::Login => {
            let data: LoginRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_login(username, data, request).await?
        }
        AuthType::Signup => {
            let data: SignupRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_signup(username, data, request).await?
        }
        AuthType::ChangePassword => {
            let data: ChangePasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_change_password(username, data).await?
        }
        AuthType::VerifyUser => {
            let data: VerifyUserRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_verify_user(username, data).await?
        }
        AuthType::ResetPassword => {
            let data: ResetPasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_reset_password(username, data).await?
        }
        AuthType::RequestPasswordReset => auth::handle_request_password_reset(username).await?,
        AuthType::VerifyOtp => {
            let data: VerifyOtpRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_verify_otp(username, data, request).await?
        }
        AuthType::Generate2Fa => auth::handle_generate_2fa(username).await?,
        AuthType::Enable2Fa => {
            let data: Enable2FaRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest)?;
            auth::handle_enable_2fa(username, data).await?
        }
        AuthType::Logout => todo!(),
        AuthType::Invalid => return Err(AuthError::InvalidRequest),
    };

    Ok(response)
}
