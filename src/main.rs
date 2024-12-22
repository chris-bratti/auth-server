use cfg_if::cfg_if;
use encryption_libs::EncryptionKey;

cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_web::cookie::Key;
        use auth_server::{
            db::db_helper::DbInstance,
            server::{
                auth_functions::{
                    get_env_variable
                },
                oauth_handlers::{
                    handle_authorization_token, handle_refresh_token, handle_register_oauth_client,
                    handle_reload_oauth_clients,
                },
            },
            AuthError, GrantType,
            RegisterNewClientRequest,TokenRequestForm,
        };
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

        use std::time::Duration;

        use actix_web::*;

        use actix_identity::IdentityMiddleware;
        use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
        use redis::{Client, Commands};
        use actix_files::Files;
        use auth_server::{app::*, server::auth_functions::{validate_oauth_token, decrypt_string}};
        use leptos::*;
        use leptos_actix::{generate_route_list, LeptosRoutes};
        use actix_web::{web, App, HttpServer, middleware::Logger, dev::{ServiceRequest},
        Error};
        use env_logger::Env;
        use actix_web_httpauth::extractors::{bearer::BearerAuth, basic::BasicAuth};
        use url::form_urlencoded;
        use actix::prelude::*;
        extern crate rand;
        use auth_server::server::actors::{
            EmailSubscriber, OAuthClientEvents, Subscribe, TaskQueueSubscriber,
        };

        use std::future::{ready, Ready};

        use actix_web::{
            dev::{forward_ready, Service, ServiceResponse, Transform},
        };
        use futures_util::future::LocalBoxFuture;

        use regex::Regex;

        use lazy_static::lazy_static;
        use auth_server::HtmlError;

        lazy_static! {
            static ref SITE_ADDR: String = get_env_variable("SITE_ADDR").unwrap();
        }

        pub struct VerifySource;

        impl<S, B> Transform<S, ServiceRequest> for VerifySource
        where
            S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
            S::Future: 'static,
            B: 'static,
        {
            type Response = ServiceResponse<B>;
            type Error = Error;
            type InitError = ();
            type Transform = VerifySourceMiddleware<S>;
            type Future = Ready<Result<Self::Transform, Self::InitError>>;

            fn new_transform(&self, service: S) -> Self::Future {
                ready(Ok(VerifySourceMiddleware { service }))
            }
        }

        pub struct VerifySourceMiddleware<S> {
            service: S,
        }

        impl<S, B> Service<ServiceRequest> for VerifySourceMiddleware<S>
        where
            S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
            S::Future: 'static,
            B: 'static,
        {
            type Response = ServiceResponse<B>;
            type Error = Error;
            type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

            forward_ready!(service);

            fn call(&self, req: ServiceRequest) -> Self::Future {
                let path_pattern = Regex::new(r"^\/v0\/.+$").unwrap();
                // Only applies to leptos server functions
                if !path_pattern.is_match(req.path()) {
                    // Verifies source matches site address
                    if req.connection_info().host().to_string() != SITE_ADDR.to_string() {
                        return Box::pin(async move { Err(Error::from(HtmlError::Forbidden)) });
                    }
                }

                let fut = self.service.call(req);

                Box::pin(async move {
                    let res = fut.await?;

                    Ok(res)
                })
            }
        }

        async fn basic_validator(
            req: ServiceRequest,
            credentials: BasicAuth,
        ) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
            // Get the provided basic auth parameters
            let client_id = credentials.user_id().to_string();
            let secret = credentials.password().unwrap();

            let redis_client = req.app_data::<web::Data<Client>>().unwrap();

            let mut con = redis_client.get_connection().unwrap();

            // Get cached secret and validate
            let stored_key: Option<String> = con.hget("oauth_clients", &client_id).unwrap();

            let stored_key = stored_key.ok_or_else(|| AuthError::InvalidToken).unwrap();

            if secret.to_string() != decrypt_string(&stored_key, EncryptionKey::OauthKey).await.unwrap() {
                return Err((actix_web::error::ErrorUnauthorized("Invalid client info"), req));
            }

            // If authorization passes, provides the client_id to the endpoint handler
            req.extensions_mut().insert(client_id);

            Ok(req)
        }

        async fn bearer_validator(
            req: ServiceRequest,
            credentials: BearerAuth
        ) -> Result<ServiceRequest, (Error, ServiceRequest)> {
            // Parse the query string and check for username
            let parsed: Vec<(String, String)> = form_urlencoded::parse(req.query_string().as_bytes())
            .into_owned()
            .collect();

            let mut username_query = None;

            for (key, value) in parsed {
                if key == "username" {
                    username_query = Some(value);
                }
            }

            // Validate provided JWT token
            match username_query {
                Some(username) => {
                    let redis_client = req.app_data::<web::Data<Client>>().unwrap();

                    if validate_oauth_token(credentials.token().to_string(), redis_client, &username).await.is_err(){
                        return Err((actix_web::error::ErrorUnauthorized("Invalid client info"), req));
                    }

                    req.extensions_mut().insert(username);

                    Ok(req)
                },
                None => {
                    Err((actix_web::error::ErrorBadRequest("Username not provided!"), req))
                }
            }

        }

    }
}

#[cfg(feature = "ssr")]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_web_httpauth::middleware::HttpAuthentication;

    let redis_connection_string =
        get_env_variable("REDIS_CONNECTION_STRING").expect("Connection string not set!");

    // Creates a shared instance of the database connection and Redis client for re-use
    let db_instance = web::Data::new(DbInstance::new());

    let redis_client =
        web::Data::new(redis::Client::open(redis_connection_string.clone()).unwrap());

    // Initialize Actors and Recipients for the event-driven events
    let task_queue_subscriber = Subscribe(
        TaskQueueSubscriber::new(redis_client.clone())
            .start()
            .recipient(),
    );

    let email_subscriber = Subscribe(EmailSubscriber {}.start().recipient());
    let oauth_client_event = OAuthClientEvents::new().start();

    oauth_client_event.send(email_subscriber).await.unwrap();
    oauth_client_event
        .send(task_queue_subscriber)
        .await
        .unwrap();

    let new_client_event = web::Data::new(oauth_client_event);

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

    // Env logger for middleware
    env_logger::init_from_env(Env::default().default_filter_or("warning"));

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
        App::new()
            // Logger middleware
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .wrap(actix_web::middleware::Logger::default())
            // External facing routes
            .service(
                web::scope("/v0")
                    .service(
                        web::scope("/users")
                            .wrap(HttpAuthentication::bearer(bearer_validator))
                            .route("/info", web::get().to(get_user_info)),
                    )
                    .service(
                        web::scope("/oauth")
                            .wrap(HttpAuthentication::basic(basic_validator))
                            .route("/token", web::post().to(get_token)),
                    )
                    .service(register_oauth_client)
                    .service(load_clients_into_redis),
            )
            .app_data(db_instance.clone())
            .app_data(redis_client.clone())
            .app_data(new_client_event.clone())
            // Uses Identity middleware for user sessions, sessions last 1 month
            .app_data(web::Data::new(leptos_options.to_owned()))
            // serve JS/WASM/CSS from `pkg`
            .service(Files::new("/pkg", format!("{site_root}/pkg")))
            // serve other assets from the `assets` directory
            .service(Files::new("/assets", site_root))
            // serve the favicon from /favicon.ico
            .service(favicon)
            .leptos_routes(leptos_options.to_owned(), routes.to_owned(), App)
            .wrap(VerifySource)
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
    })
    .bind_openssl(&addr, ssl_builder)?
    .run()
    .await
}

// Placeholder for endpoints accessing user information
#[cfg(feature = "ssr")]
async fn get_user_info(
    db_instance: web::Data<DbInstance>,
    request: HttpRequest,
) -> Result<impl Responder, AuthError> {
    use auth_server::UserInfoResponse;

    let username = request
        .extensions()
        .get::<String>()
        .ok_or_else(|| AuthError::InvalidRequest("Username not present in request!".to_string()))?
        .to_string();

    let user = db_instance
        .find_user_by_username(&username)
        .await?
        .ok_or_else(|| AuthError::InvalidRequest("User not found!".to_string()))?;

    Ok(HttpResponse::Ok().json(UserInfoResponse {
        success: true,
        user_data: user,
        timestamp: chrono::Utc::now().timestamp(),
    }))
}

// Handler for getting oauth token using authorization code or refresh token
#[cfg(feature = "ssr")]
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
        GrantType::Invalid => {
            return Err(AuthError::InvalidRequest("Invalid grant_type".to_string()));
        }
    };

    Ok(response)
}

// Endpoint to register a new OAuth client
#[cfg(feature = "ssr")]
#[post("/clients/register")]
async fn register_oauth_client(
    register_client_request: web::Json<RegisterNewClientRequest>,
    oauth_created_event: web::Data<Addr<OAuthClientEvents>>,
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

    let response = handle_register_oauth_client(
        register_client_request.into_inner(),
        &db_instance,
        oauth_created_event,
    )
    .await?;

    Ok(HttpResponse::Ok().json(response))
}

// Internal endpoint to reload oauth clients into redis cache
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
