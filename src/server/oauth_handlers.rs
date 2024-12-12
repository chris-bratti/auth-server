use crate::db::db_helper::DbInstance;

use core::result::Result::Ok;
use std::sync::Arc;

use actix_web::{web, HttpResponse, Result};
use redis::{Client, Commands, RedisResult};
use tokio::task;

use crate::{server::auth_functions::*, AuthError};

use crate::{
    AuthorizationCodeResponse, OAuthRedirect, RefreshTokenResponse, RegisterNewClientRequest,
    RegisterNewClientResponse, ReloadOauthClientsResponse,
};

pub async fn handle_authorization_token(
    authorization_code: String,
    client_id: &String,
    db_instance: &web::Data<DbInstance>,
    redis_client: &web::Data<Client>,
) -> Result<HttpResponse, AuthError> {
    let mut con = redis_client.get_connection()?;

    let username: Option<String> = con.hget(&client_id, &authorization_code)?;

    let username = username.ok_or_else(|| AuthError::InvalidCredentials)?;

    let redis_id = client_id.clone();

    task::spawn_blocking(move || {
        let result: RedisResult<()> = con.hdel(redis_id, authorization_code);
        if let Err(err) = result {
            eprintln!("Error removing Authorization Code from redis: {:?}", err)
        }
    });

    let expiry = chrono::Utc::now().timestamp() + 600;
    let access_token = generate_oauth_token(client_id, expiry, &username).await?;
    let mut refresh_token = generate_token();

    let token_id = generate_token()
        .get(0..8)
        .expect("Error parsing string!")
        .to_string();

    // Clone the data necessary for the async work
    let stored_instance = Arc::clone(db_instance);
    let stored_id = client_id.clone();
    let stored_token = refresh_token.clone();
    let stored_token_id = token_id.clone();
    let stored_username = username.clone();

    tokio::spawn(async move {
        if let Err(err) = stored_instance
            .add_refresh_token(
                &stored_id,
                &stored_token,
                &stored_token_id,
                &stored_username,
            )
            .await
        {
            eprintln!("Error saving refresh token to DB: {:?}", err);
        }
    });

    refresh_token.push_str(token_id.as_str());

    Ok(HttpResponse::Ok().json(AuthorizationCodeResponse {
        success: true,
        username,
        access_token,
        refresh_token,
        expiry,
    }))
}

pub async fn handle_refresh_token(
    db_instance: &web::Data<DbInstance>,
    client_id: &String,
    refresh_token: &String,
) -> Result<HttpResponse, AuthError> {
    // Token Id is stored in the last 10 characters of the token given to the client
    let (provided_token, token_id) = refresh_token
        .split_at_checked(refresh_token.len() - 8)
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let (stored_token, username) = db_instance
        .get_username_from_refresh_token(&client_id, &token_id.to_string())
        .await?;

    if stored_token != provided_token {
        return Err(AuthError::InvalidCredentials);
    }

    let expiry = chrono::Utc::now().timestamp() + 600;
    let access_token = generate_oauth_token(client_id, expiry, &username).await?;

    Ok(HttpResponse::Ok().json(RefreshTokenResponse {
        success: true,
        access_token,
        username,
        expiry,
    }))
}

pub async fn handle_register_oauth_client(
    register_client_request: RegisterNewClientRequest,
    db_instance: &web::Data<DbInstance>,
    redis_client: &web::Data<Client>,
) -> Result<HttpResponse, AuthError> {
    // Generate a random but short id
    let client_id = generate_token()
        .get(0..10)
        .expect("Error parsing string!")
        .to_string();

    // Generate longer secret
    let client_secret = generate_token();

    let RegisterNewClientRequest {
        app_name,
        contact_email,
        redirect_url,
    } = register_client_request;

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

    let mut con = redis_client
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

pub async fn handle_request_oauth_token(
    client_id: String,
    username: String,
    state: String,
    redis_client: &web::Data<Client>,
) -> Result<OAuthRedirect, AuthError> {
    let mut con = redis_client.get_connection()?;

    // Check that client exists
    let cached_redirect_url: Option<String> = con.hget("redirect_urls", &client_id)?;

    let redirect_url = cached_redirect_url.ok_or_else(|| AuthError::InvalidCredentials)?;

    // Generate auth code and store it in Redis
    let authorization_code = generate_token();

    () = con.hset(&client_id, &authorization_code, &username)?;
    () = con.hexpire(
        &client_id,
        600,
        redis::ExpireOption::NONE,
        &authorization_code,
    )?;

    Ok(OAuthRedirect {
        authorization_code,
        state,
        redirect_url,
    })
}

pub async fn handle_reload_oauth_clients(
    db_instance: &web::Data<DbInstance>,
    redis_client: &web::Data<Client>,
) -> Result<HttpResponse, AuthError> {
    let oauth_clients = load_oauth_clients(db_instance).await.unwrap();
    let mut con = redis_client.get_connection()?;

    println!("Reloading oauth clients");

    let mut clients_loaded = 0;

    for (client_id, (client_secret, redirect_url)) in &oauth_clients {
        () = con.hset("oauth_clients", client_id, client_secret)?;
        () = con.hset("redirect_urls", client_id, redirect_url)?;
        clients_loaded = clients_loaded + 1;
    }

    Ok(HttpResponse::Ok().json(ReloadOauthClientsResponse {
        success: true,
        clients_loaded,
    }))
}
