use actix_web::cookie::Key;
use auth_server::{auth, server::helpers::get_env_variable};
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
            .service(auth::login)
            .service(auth::signup)
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

/*
#[get("/")]
async fn index(user: Option<Identity>) -> impl Responder {
    if let Some(user) = user {
        let id = user.id().unwrap();
        println!("{}", &id);
        format!("Welcome! {}", id)
    } else {
        println!("Welcome anon");
        "Welcome Anonymous!".to_owned()
    }
}

#[post("/login")]
async fn login(request: HttpRequest) -> impl Responder {
    Identity::login(&request.extensions(), "User1".into()).expect("ohno");
    HttpResponse::Ok()
}

#[post("/logout")]
async fn logout(user: Identity) -> impl Responder {
    println!("Bye bye");
    user.logout();
    HttpResponse::Ok()
}
    */
