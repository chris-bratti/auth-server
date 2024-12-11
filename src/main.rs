use actix_web::cookie::Key;
use auth_server::{
    auth::{self, handle_authorization_token},
    db::db_helper::DbInstance,
    server::auth_functions::{
        add_api_key, generate_token, get_env_variable, hash_string, load_api_keys,
        load_oauth_clients, validate_client_info, verify_hash,
    },
    AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest, GrantType,
    LoginRequest, OAuthRequest, OAuthResponse, RegisterNewClientRequest, RegisterNewClientResponse,
    ReloadOauthClientsResponse, ResetPasswordRequest, SignupRequest, TokenRequestForm,
    VerifyOtpRequest, VerifyUserRequest,
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

    let db_instance = web::Data::new(DbInstance::new());

    // Matches against a given command
    match &cli.command {
        // If app was run with add-api-key command, checks auth_key and adds new api key
        Some(CliArguments::AddApiKey { app_name, auth_key }) => {
            let mut con = REDIS_CLIENT.get_connection().unwrap();
            let admin_key: String = con.get("admin_key").unwrap();
            if verify_hash(auth_key, &admin_key).unwrap() {
                let api_key = add_api_key(app_name, db_instance)
                    .await
                    .expect("Error adding api key!");
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
    load_api_keys_into_redis(&db_instance)
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
            .app_data(db_instance.clone())
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
            .service(register_oauth_client)
            .service(load_clients_into_redis)
            .service(oauth_request)
            .service(get_token)
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
    db_instance: web::Data<DbInstance>,
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
            auth::handle_login(username, data, request, db_instance).await?
        }
        AuthType::Signup => {
            let data: SignupRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_signup(username, data, request, db_instance).await?
        }
        AuthType::ChangePassword => {
            let data: ChangePasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_change_password(username, data, db_instance).await?
        }
        AuthType::VerifyUser => {
            let data: VerifyUserRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_verify_user(username, data, db_instance).await?
        }
        AuthType::ResetPassword => {
            let data: ResetPasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_reset_password(username, data, db_instance).await?
        }
        AuthType::RequestPasswordReset => {
            auth::handle_request_password_reset(username, db_instance).await?
        }
        AuthType::VerifyOtp => {
            let data: VerifyOtpRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_verify_otp(username, data, request, db_instance).await?
        }
        AuthType::Generate2Fa => auth::handle_generate_2fa(username, db_instance).await?,
        AuthType::Enable2Fa => {
            let data: Enable2FaRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth::handle_enable_2fa(username, data, db_instance).await?
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

#[post("/token")]
async fn get_token(
    form: web::Form<TokenRequestForm>,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    let client_id = validate_client_info(auth_header.to_string()).await?;

    let TokenRequestForm {
        grant_type,
        refresh_token,
        authorization_code,
    } = form.into_inner();

    let response = match GrantType::from(grant_type.as_str()) {
        GrantType::AuthorizationCode => {
            let authorization_code = authorization_code.ok_or_else(|| {
                AuthError::InvalidRequest("Missing authorization_code".to_string())
            })?;
            handle_authorization_token(authorization_code, &client_id, &db_instance).await?
        }
        GrantType::RefreshToken => todo!(),
        GrantType::Invalid => todo!(),
    };

    Ok(response)
}

#[post("/oauth")]
async fn oauth_request(oauth_request: web::Query<OAuthRequest>) -> Result<HttpResponse, AuthError> {
    //Simulate login
    let username = "testuser123";

    let OAuthRequest { client_id, state } = oauth_request.into_inner();

    let mut con = REDIS_CLIENT
        .get_connection()
        .expect("Error getting redis connection!");

    let cached_key: Option<String> = con.hget("oauth_clients", &client_id)?;

    if cached_key.is_none() {
        return Err(AuthError::InvalidCredentials);
    }

    let authorization_code = generate_token();

    //() = con.set_ex(&client_id, &authorization_code, 600)?;
    () = con.hset(
        "auth_codes",
        format!("{}:{}", &client_id, &username),
        &authorization_code,
    )?;
    () = con.hexpire("auth_codes", 20, redis::ExpireOption::NONE, &client_id)?;

    Ok(HttpResponse::Ok().json(OAuthResponse {
        success: true,
        authorization_code,
        state,
    }))
}

#[post("/oauth/register")]
async fn register_oauth_client(
    register_client_request: web::Json<RegisterNewClientRequest>,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let admin_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    if admin_key != get_env_variable("ADMIN_KEY").unwrap() {
        return Err(AuthError::InvalidCredentials);
    }

    let client_id = generate_token()
        .get(0..8)
        .expect("Error parsing string!")
        .to_string();

    let client_secret = generate_token();

    let RegisterNewClientRequest {
        app_name,
        contact_email,
        redirect_url,
    } = register_client_request.into_inner();

    let encrypted_secret = db_instance
        .add_new_oauth_client(
            &app_name,
            &contact_email,
            &client_id,
            &client_secret,
            &redirect_url,
        )
        .await
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    let mut con = REDIS_CLIENT
        .get_connection()
        .expect("Error getting redis connection!");

    () = con
        .hset("oauth_clients", &client_id, &encrypted_secret)
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    //println!("Implement pubsub model");

    Ok(HttpResponse::Ok().json(RegisterNewClientResponse {
        success: true,
        client_id,
        client_secret,
        redirect_url,
    }))
}

#[post("/internal/reload-clients")]
async fn load_clients_into_redis(
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
) -> Result<HttpResponse, AuthError> {
    let admin_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::InvalidRequest(
            "invalid header value".to_string(),
        ))?;

    if admin_key != get_env_variable("ADMIN_KEY").unwrap() {
        return Err(AuthError::InvalidCredentials);
    }

    let oauth_clients = load_oauth_clients(db_instance).await.unwrap();
    let mut con = REDIS_CLIENT
        .get_connection()
        .map_err(|err| AuthError::InternalServerError(err.to_string()))?;

    let mut clients_loaded = 0;

    for (client_id, client_secret) in &oauth_clients {
        () = con
            .hset("oauth_clients", client_id, client_secret)
            .map_err(|err| AuthError::InternalServerError(err.to_string()))?;
        clients_loaded = clients_loaded + 1;
    }

    Ok(HttpResponse::Ok().json(ReloadOauthClientsResponse {
        success: true,
        clients_loaded,
    }))
}

async fn load_api_keys_into_redis(db_instance: &web::Data<DbInstance>) -> Result<(), RedisError> {
    let api_keys = load_api_keys(db_instance).await.unwrap();
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
