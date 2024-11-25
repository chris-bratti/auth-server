use actix_web::cookie::Key;
use auth_server::{
    auth::{self},
    server::auth_functions::{add_api_key, get_env_variable, load_api_keys, verify_api_key},
    ApiKeys, AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest,
    LoginRequest, ResetPasswordRequest, SignupRequest, VerifyOtpRequest, VerifyUserRequest,
};
use clap::{Parser, Subcommand};

use std::time::Duration;

use actix_web::*;

use actix_identity::IdentityMiddleware;
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};

#[derive(Parser)]
#[clap(name = "AuthServer", version = "1.0", author = "You")]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    AddApiKey {
        #[clap(long)]
        app_name: String,
        #[clap(long)]
        api_key: String,
        #[clap(long)]
        auth_key: String,
    },
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Generate the list of routes in your Leptos App

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::AddApiKey {
            app_name,
            api_key,
            auth_key,
        }) => {
            if *auth_key == get_env_variable("ADMIN_KEY").expect("Error getting ADMIN_KEY") {
                add_api_key(app_name, api_key)
                    .await
                    .expect("Error adding api key!");
            } else {
                println!("Invalid ADMIN_KEY!");
            }
            return Ok(());
        }
        None => {
            println!("Starting server...");
        }
    }

    let secret_key = get_secret_key();
    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    println!("Starting server on port 8080");

    let api_keys = web::Data::new(load_api_keys().await.unwrap());

    HttpServer::new(move || {
        App::new()
            .app_data(api_keys.clone())
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
    api_keys: web::Data<ApiKeys>,
) -> Result<HttpResponse, AuthError> {
    let request_type = request
        .headers()
        .get("X-Request-Type")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest)?;

    let api_key = request
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest)?;

    let app_name = request
        .headers()
        .get("X-App-Name")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest)?;

    if !verify_api_key(String::from(app_name), String::from(api_key), &api_keys).await? {
        return Err(AuthError::InvalidCredentials);
    }

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
