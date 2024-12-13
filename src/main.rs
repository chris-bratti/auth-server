use actix_web_httpauth::headers::www_authenticate::Challenge;
use auth_server::{
    db::schema::oauth_clients::client_secret, server::auth_functions::decrypt_string, EncryptionKey,
};
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_web::cookie::Key;
        use auth_server::{
            db::db_helper::DbInstance,
            server::{
                auth_functions::{
                    add_api_key, get_env_variable, hash_string, load_api_keys,
                    verify_hash,
                },
                auth_handlers,
                oauth_handlers::{
                    handle_authorization_token, handle_refresh_token, handle_register_oauth_client,
                    handle_reload_oauth_clients, handle_request_oauth_token,
                },
            },
            AuthError, AuthRequest, AuthType, ChangePasswordRequest, Enable2FaRequest, GrantType,
            LoginRequest, OAuthRedirect, OAuthRequest, RegisterNewClientRequest, ResetPasswordRequest,
            SignupRequest, TokenRequestForm, VerifyOtpRequest, VerifyUserRequest,
        };
        use clap::{Parser, Subcommand};
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
        use web::Redirect;

        use std::time::Duration;

        use actix_web::*;

        use actix_identity::IdentityMiddleware;
        use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
        use redis::{Client, Commands, RedisError};
        use actix_files::Files;
        use auth_server::app::*;
        use leptos::*;
        use leptos_actix::{generate_route_list, LeptosRoutes};
        use actix_web::{web, App, HttpServer};
        use actix_web::middleware::Logger;
        use env_logger::Env;
        use actix_web_httpauth::extractors::bearer::BearerAuth;
        use actix_web_httpauth::extractors::bearer;
        use actix_web_httpauth::extractors::AuthenticationError;
        use actix_web_httpauth::extractors::basic::BasicAuth;
        use auth_server::server::auth_functions::validate_oauth_token;



        use std::future::{ready, Ready};

        use actix_web::{
            dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
            Error,
        };
        use futures_util::future::LocalBoxFuture;

        async fn basic_validator(
            req: ServiceRequest,
            credentials: BasicAuth,
        ) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
            eprintln!("{credentials:?}");
            let client_id = credentials.user_id().to_string();
            let secret = credentials.password().unwrap();

            let redis_client = req.app_data::<web::Data<Client>>().unwrap();

            let mut con = redis_client.get_connection().unwrap();

            let stored_key: Option<String> = con.hget("oauth_clients", &client_id).unwrap();

            let stored_key = stored_key.ok_or_else(|| AuthError::InvalidToken).unwrap();

            println!("{stored_key}");

            if secret.to_string() != decrypt_string(&stored_key, EncryptionKey::OauthKey).await.unwrap() {
                return Err((actix_web::error::ErrorUnauthorized("Invalid client info"), req));
            }

            println!("{} and {}", client_id, secret);

            req.extensions_mut().insert(client_id);

            Ok(req)
        }

        async fn bearer_validator(
            req: ServiceRequest,
            credentials: BearerAuth
        ) -> Result<ServiceRequest, (Error, ServiceRequest)> {
            if credentials.token() == "mF_9.B5f-4.1JqM" {
                Ok(req)
            } else {
                let config = req.app_data::<bearer::Config>()
                    .cloned()
                    .unwrap_or_default()
                    .scope("urn:example:channel=HBO&urn:example:rating=G,PG-13");

                Err((AuthenticationError::from(config).into(), req))
            }
        }

    }
}

#[cfg(feature = "ssr")]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_cors::Cors;
    use actix_web_httpauth::{extractors::basic, middleware::HttpAuthentication};

    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");

    // Creates a shared instance of the database connection and Redis client for re-use
    let db_instance = web::Data::new(DbInstance::new());

    let redis_client =
        web::Data::new(redis::Client::open(redis_connection_string.clone()).unwrap());

    // Leptos connection stuff, sets site address information
    let conf = get_configuration(None).await.unwrap();
    let addr = conf.leptos_options.site_addr;

    // Generate the list of routes in your Leptos App
    let routes = generate_route_list(App);

    // Get the Redis key, uses a determinable key to maintain sessions between
    // HA replicas as well as session between server restarts
    let secret_key = Key::from(
        get_env_variable("REDIS_KEY")
            .expect("REDIS_KEY not set!")
            .as_bytes(),
    );

    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Sets the admin_key for the session
    let mut con = redis_client.get_connection().unwrap();
    let admin_key = hash_string(&get_env_variable("ADMIN_KEY").unwrap())
        .await
        .unwrap();
    let _: () = con.set("admin_key", admin_key).unwrap();

    // Creates new session store for Actix, using Redis as a backend
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    // Builds SSL using private key and cert
    let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    ssl_builder
        .set_private_key_file("certs/private.pem", SslFiletype::PEM)
        .unwrap();
    ssl_builder
        .set_certificate_chain_file("certs/cert.pem")
        .unwrap();

    HttpServer::new(move || {
        let leptos_options = &conf.leptos_options;
        let site_root = &leptos_options.site_root;
        let cors = Cors::default()
            .allowed_origin("https://localhost:3000")
            .allowed_methods(vec!["GET", "POST"])
            .max_age(3600);
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .wrap(actix_web::middleware::Logger::default())
            // serve JS/WASM/CSS from `pkg`
            .service(Files::new("/pkg", format!("{site_root}/pkg")))
            // serve other assets from the `assets` directory
            .service(Files::new("/assets", site_root))
            // serve the favicon from /favicon.ico
            .service(favicon)
            .leptos_routes(leptos_options.to_owned(), routes.to_owned(), App)
            .service(web::scope("/api").wrap(cors))
            .app_data(web::Data::new(leptos_options.to_owned()))
            // Add in the shared connection information
            .app_data(db_instance.clone())
            .app_data(redis_client.clone())
            // Uses Identity middleware for user sessions, sessions last 1 month
            .wrap(
                IdentityMiddleware::builder()
                    .login_deadline(Some(Duration::new(259200, 0)))
                    .build(),
            )
            // Uses Session middleware for all Session info, uses Redis as a backend
            .wrap(
                SessionMiddleware::builder(store.clone(), secret_key.clone())
                    .cookie_secure(true)
                    .session_lifecycle(
                        PersistentSession::default()
                            .session_ttl(actix_web::cookie::time::Duration::weeks(2)),
                    )
                    .build(),
            )
            .service(register_oauth_client)
            .service(load_clients_into_redis)
            .service(auth_request)
            .service(
                web::scope("/token")
                    .wrap(HttpAuthentication::basic(basic_validator))
                    .route("/", web::post().to(get_token)),
            )
    })
    .bind_openssl(&addr, ssl_builder)?
    .run()
    .await
}

// Main Auth endpoint, requires a request_type, api_key, and app_name
#[post("/auth")]
async fn auth_request(
    auth_payload: web::Json<AuthRequest>,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
    redis_client: web::Data<Client>,
) -> Result<HttpResponse, AuthError> {
    let request_type = request
        .headers()
        .get("X-Request-Type")
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

    let AuthRequest { username, data } = auth_payload.into_inner();

    let response = match AuthType::from(request_type) {
        AuthType::Login => {
            todo!()
            /*
            let data: LoginRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_login(username, password, request, db_instance).await?
            */
        }
        AuthType::Signup => {
            todo!()
            /*
            let data: SignupRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_signup(username, data, request, db_instance).await?
            */
        }
        AuthType::ChangePassword => {
            let data: ChangePasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_change_password(username, data, db_instance).await?
        }
        AuthType::VerifyUser => {
            let data: VerifyUserRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_verify_user(username, data, db_instance).await?
        }
        AuthType::ResetPassword => {
            let data: ResetPasswordRequest =
                serde_json::from_value(data.expect("Missing data field"))
                    .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_reset_password(username, data, db_instance).await?
        }
        AuthType::RequestPasswordReset => {
            auth_handlers::handle_request_password_reset(username, db_instance).await?
        }
        AuthType::VerifyOtp => {
            todo!()
            /*
            let data: VerifyOtpRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_verify_otp(username, data, request, db_instance).await?
            */
        }
        AuthType::Generate2Fa => auth_handlers::handle_generate_2fa(username, db_instance).await?,
        AuthType::Enable2Fa => {
            let data: Enable2FaRequest = serde_json::from_value(data.expect("Missing data field"))
                .map_err(|_| AuthError::InvalidRequest("invalid request body".to_string()))?;
            auth_handlers::handle_enable_2fa(username, data, db_instance).await?
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

async fn get_token(
    form: web::Form<TokenRequestForm>,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
    redis_client: web::Data<Client>,
) -> Result<impl Responder, AuthError> {
    let client_id = request
        .extensions()
        .get::<String>()
        .ok_or_else(|| AuthError::InvalidRequest("Missing client header".to_string()))?
        .to_string();

    println!("Got a client idL {client_id}");

    //let client_id = validate_client_info(auth_header.to_string(), &redis_client).await?;

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
            handle_authorization_token(authorization_code, &client_id, &db_instance, &redis_client)
                .await?
        }
        GrantType::RefreshToken => {
            let refresh_token = refresh_token
                .ok_or_else(|| AuthError::InvalidRequest("Missing refresh token!".to_string()))?;
            handle_refresh_token(&db_instance, &client_id, &refresh_token).await?
        }
        GrantType::Invalid => todo!(),
    };

    Ok(response)
}

/*
#[cfg(feature = "ssr")]
#[post("/oauth")]
async fn oauth_request(
    oauth_request: web::Query<OAuthRequest>,
    redis_client: web::Data<Client>,
) -> Result<impl Responder, AuthError> {
    // Simulate login
    // Todo: Implement Leptos for login
    let username = "testuser123".to_string();

    let OAuthRequest { client_id, state } = oauth_request.into_inner();

    let OAuthRedirect {
        authorization_code,
        state,
        redirect_url,
    } = handle_request_oauth_token(client_id, username, state, &redis_client).await?;

    println!("Redirecting to: {redirect_url}?code={authorization_code}&state={state}");

    Ok(Redirect::to(format!(
        "{redirect_url}?code={authorization_code}&state={state}"
    )))
}
    */

#[cfg(feature = "ssr")]
#[post("/oauth/register")]
async fn register_oauth_client(
    register_client_request: web::Json<RegisterNewClientRequest>,
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
    redis_client: web::Data<Client>,
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

    let response = handle_register_oauth_client(
        register_client_request.into_inner(),
        &db_instance,
        &redis_client,
    )
    .await?;

    tokio::spawn(async move {
        if let Err(err) = handle_reload_oauth_clients(&db_instance, &redis_client).await {
            eprintln!("Error reloading clients!: {err}");
        } else {
            println!("Clients successfully reloaded");
        }
    });

    Ok(response)
}

#[cfg(feature = "ssr")]
#[post("/internal/reload-clients")]
async fn load_clients_into_redis(
    request: HttpRequest,
    db_instance: web::Data<DbInstance>,
    redis_client: web::Data<Client>,
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

    handle_reload_oauth_clients(&db_instance, &redis_client).await
}

#[cfg(feature = "ssr")]
#[actix_web::get("favicon.ico")]
async fn favicon(
    leptos_options: actix_web::web::Data<leptos::LeptosOptions>,
) -> actix_web::Result<actix_files::NamedFile> {
    let leptos_options = leptos_options.into_inner();
    let site_root = &leptos_options.site_root;
    Ok(actix_files::NamedFile::open(format!(
        "{site_root}/favicon.ico"
    ))?)
}

#[cfg(not(any(feature = "ssr", feature = "csr")))]
pub fn main() {
    // no client-side main function
    // unless we want this to work with e.g., Trunk for pure client-side testing
    // see lib.rs for hydration function instead
    // see optional feature `csr` instead
}

#[cfg(all(not(feature = "ssr"), feature = "csr"))]
pub fn main() {
    // a client-side main function is required for using `trunk serve`
    // prefer using `cargo leptos serve` instead
    // to run: `trunk serve --open --features csr`
    use auth_server::app::*;

    console_error_panic_hook::set_once();

    leptos::mount_to_body(App);
}
