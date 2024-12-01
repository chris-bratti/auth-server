use actix_web::cookie::Key;
use auth_server::{
    auth::{self},
    server::auth_functions::{
        add_api_key, get_env_variable, hash_string, load_api_keys, verify_hash,
    },
    AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest, LoginRequest,
    ResetPasswordRequest, SignupRequest, VerifyOtpRequest, VerifyUserRequest,
};
use clap::{Parser, Subcommand};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use std::time::Duration;

use actix_web::*;

use actix_identity::IdentityMiddleware;
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use redis::{Commands, RedisError};

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

use lazy_static::lazy_static;

lazy_static! {
    static ref REDIS_CLIENT: redis::Client = redis::Client::open(
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!")
    )
    .unwrap();
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
            let mut con = REDIS_CLIENT.get_connection().unwrap();
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

    // Get the Redis key, uses a determinable key to maintain sessions between
    // k8s replicas
    let secret_key = Key::from(
        get_env_variable("REDIS_KEY")
            .expect("REDIS_KEY not set!")
            .as_bytes(),
    );

    // Sets the admin_key for the session
    let mut con = REDIS_CLIENT.get_connection().unwrap();
    let admin_key = hash_string(&get_env_variable("ADMIN_KEY").unwrap())
        .await
        .unwrap();
    let _: () = con.set("admin_key", admin_key).unwrap();

    // Creates new session store for Actix, using Redis as a backend
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    // Loads API keys from the database into Redis
    load_api_keys_into_redis()
        .await
        .expect("Error loading keys into Redis!");

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
    .bind_openssl("0.0.0.0:8080", builder)?
    .run()
    .await
}

// Main Auth endpoint, requires a request_type, api_key, and app_name
#[post("/auth")]
async fn auth_request(
    auth_payload: web::Json<AuthRequest>,
    request: HttpRequest,
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

    if !valid_api_key(api_key, app_name)? {
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

async fn load_api_keys_into_redis() -> Result<(), RedisError> {
    let api_keys = load_api_keys().await.unwrap();
    let mut con = REDIS_CLIENT.get_connection()?;
    if con.exists("api_keys")? {
        return Ok(());
    }
    let redis_hash_key = "api_keys";
    for (app, hash) in &api_keys {
        () = con.hset(redis_hash_key, app, hash)?;
    }
    Ok(())
}

fn valid_api_key(api_key: &str, app_name: &str) -> Result<bool, AuthError> {
    let mut con = REDIS_CLIENT
        .get_connection()
        .map_err(|_| AuthError::InternalServerError("Backend error".to_string()))?;

    let cached_key: Option<String> = con
        .hget("api_keys", app_name)
        .map_err(|_| AuthError::InternalServerError("Backend error".to_string()))?;

    match cached_key {
        None => Ok(false),
        Some(hashed_key) => verify_hash(&String::from(api_key), &hashed_key)
            .map_err(|_| AuthError::InternalServerError("Error validating hash".to_string())),
    }
}
