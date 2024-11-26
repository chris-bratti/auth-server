use actix_web::cookie::Key;
use auth_server::{
    auth::{self},
    server::auth_functions::{
        add_api_key, get_env_variable, hash_string, load_api_keys, verify_api_key, verify_hash,
    },
    ApiKeys, AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest,
    LoginRequest, ResetPasswordRequest, SignupRequest, VerifyOtpRequest, VerifyUserRequest,
};
use clap::{Parser, Subcommand};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use std::{sync::RwLock, time::Duration};

use actix_web::*;

use actix_identity::IdentityMiddleware;
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use redis::Commands;

// Parses CLI arguments
#[derive(Parser)]
#[clap(name = "AuthServer", version = "1.0", author = "You")]
struct Cli {
    #[clap(subcommand)]
    command: Option<CliArguments>,
}

// Struct for CLI arguments
#[derive(Subcommand)]
enum CliArguments {
    AddApiKey {
        #[clap(long)]
        app_name: String,
        #[clap(long)]
        auth_key: String,
    },
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");

    // Matches against a given command
    match &cli.command {
        // If app was run with add-api-key command, checks auth_key and adds new api key
        Some(CliArguments::AddApiKey { app_name, auth_key }) => {
            let client = redis::Client::open(redis_connection_string.clone()).unwrap();
            let mut con = client.get_connection().unwrap();
            let admin_key: String = con.get("admin_key").unwrap();
            if verify_hash(auth_key, &admin_key).unwrap() {
                let api_key = add_api_key(app_name).await.expect("Error adding api key!");
                println!("New API Key: {}", api_key);
            } else {
                println!("Invalid ADMIN_KEY!");
            }
            return Ok(());
        }
        // If no command given, starts the server
        None => {
            println!("Starting server on port 8080");
        }
    }

    let secret_key = get_secret_key();

    // Sets the admin_key for the session
    let client = redis::Client::open(redis_connection_string.clone()).unwrap();
    let mut con = client.get_connection().unwrap();
    let admin_key = hash_string(&get_env_variable("ADMIN_KEY").unwrap())
        .await
        .unwrap();
    let _: () = con.set("admin_key", admin_key).unwrap();

    // Creates new session store for Actix, using Redis as a backend
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    // Loads API keys from the database into a global shared state
    let api_keys = web::Data::new(ApiKeys {
        api_keys: RwLock::new(load_api_keys().await.unwrap()),
    });

    // Builds SSL using private key and cert
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("certs/private.pem", SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("certs/cert.pem")
        .unwrap();

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
            .service(reload_api_keys)
    })
    .bind_openssl("0.0.0.0:8080", builder)?
    .run()
    .await
}

fn get_secret_key() -> Key {
    return Key::generate();
}

// Main Auth endpoint, requires a request_type, api_key, and app_name
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
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    let api_key = request
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    let app_name = request
        .headers()
        .get("X-App-Name")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    if !verify_api_key(String::from(app_name), String::from(api_key), &api_keys).await? {
        return Err(AuthError::InvalidCredentials);
    }

    let AuthRequest { username, data } = auth_payload.into_inner();

    let response = match AuthType::from(request_type) {
        AuthType::Login => {
            let data: LoginRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_login(username, data, request).await?
        }
        AuthType::Signup => {
            let data: SignupRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_signup(username, data, request).await?
        }
        AuthType::ChangePassword => {
            let data: ChangePasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_change_password(username, data).await?
        }
        AuthType::VerifyUser => {
            let data: VerifyUserRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_verify_user(username, data).await?
        }
        AuthType::ResetPassword => {
            let data: ResetPasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_reset_password(username, data).await?
        }
        AuthType::RequestPasswordReset => auth::handle_request_password_reset(username).await?,
        AuthType::VerifyOtp => {
            let data: VerifyOtpRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_verify_otp(username, data, request).await?
        }
        AuthType::Generate2Fa => auth::handle_generate_2fa(username).await?,
        AuthType::Enable2Fa => {
            let data: Enable2FaRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_enable_2fa(username, data).await?
        }
        AuthType::Logout => todo!(),
        AuthType::Invalid => {
            return Err(AuthError::InvalidRequest(
                "invalid request type".to_string(),
            ))
        }
    };

    Ok(response)
}

// Internal endpoint to refresh Api keys, requires a valid admin key
#[post("/internal/reload-keys")]
async fn reload_api_keys(
    api_keys: web::Data<ApiKeys>,
    request: HttpRequest,
) -> Result<HttpResponse, AuthError> {
    let admin_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");

    let client = redis::Client::open(redis_connection_string.clone()).unwrap();
    let mut con = client.get_connection().unwrap();
    let stored_admin_key: String = con.get("admin_key").unwrap();

    // Checks basic encryption against env key
    if !verify_hash(&admin_key.to_string(), &stored_admin_key).unwrap() {
        return Err(AuthError::InvalidCredentials);
    }

    // Refresh all admin keys
    api_keys.refresh_keys(load_api_keys().await.unwrap());

    Ok(HttpResponse::Ok().json(String::from("API keys reloaded")))
}
