use crate::server::auth_handlers::handle_signup;
use crate::{AuthError, AuthResponse, LoginResponse, VerifyOtpRequest};
use crate::{OAuthRedirect, OAuthRequest};
use cfg_if::cfg_if;
use leptos::server;
use leptos::ServerFnError;
cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_web::{web, HttpRequest, HttpResponse};
        use leptos::{use_context};
        use leptos_actix::extract;
        use actix_session::Session;
        use actix_session::SessionExt;
        use crate::server::oauth_handlers::handle_request_oauth_token;


        use crate::{
            db::db_helper::DbInstance,
            server::auth_handlers::{handle_login, handle_verify_otp},
        };
    }
}

#[server]
pub async fn test() -> Result<(), ServerFnError> {
    let session: Session = extract().await.unwrap();
    let key: String = session.get("example-key").unwrap().unwrap();
    println!("{:#?}", key);
    Ok(())
}

#[server]
pub async fn first_test() -> Result<(), ServerFnError> {
    let session: Session = extract().await.unwrap();
    let value = "Random value";
    session.insert("example-key", value).unwrap();
    println!("{:#?}", session.entries());
    Ok(())
}

#[server(Login, "/api")]
pub async fn login(
    username: String,
    password: String,
    client_id: String,
    state: String,
) -> Result<String, ServerFnError<AuthError>> {
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;
    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    let two_factor_enabled = handle_login(&username, password, req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    if two_factor_enabled {
        return Ok(username);
    } else {
        // If not redirected from another app, go to user page
        if client_id.is_empty() && state.is_empty() {
            leptos_actix::redirect("/user");
        } else {
            // If part of OAuth flow, redirect to the client's redirect_url
            let redis_client: web::Data<redis::Client> = extract().await.map_err(|_| {
                AuthError::InternalServerError("Unable to find session data".to_string())
                    .to_server_fn_error()
            })?;
            let OAuthRedirect {
                authorization_code,
                state,
                redirect_url,
            } = handle_request_oauth_token(client_id, username, state, &redis_client).await?;

            println!("Redirecting to: {redirect_url}?code={authorization_code}&state={state}");

            leptos_actix::redirect(
                format!("{redirect_url}?code={authorization_code}&state={state}").as_str(),
            );
        }

        return Ok("".to_string());
    }
}

#[server(Signup, "/api")]
async fn signup(
    username: String,
    first_name: String,
    last_name: String,
    email: String,
    password: String,
    confirm_password: String,
    client_id: Option<String>,
    state: Option<String>,
) -> Result<(), ServerFnError<AuthError>> {
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;
    // Get current context
    let Some(req) = use_context::<actix_web::HttpRequest>() else {
        return Err(ServerFnError::WrappedServerError(
            AuthError::InternalServerError("No HttpRequest found in current context".to_string()),
        ));
    };

    handle_signup(
        &username,
        first_name,
        last_name,
        email,
        password,
        confirm_password,
        req,
        db_instance,
    )
    .await?;

    if client_id.is_none() && state.is_none() {
        leptos_actix::redirect("/user");
    } else {
        let client_id = client_id.unwrap();
        let state = state.unwrap();
        // If part of OAuth flow, redirect to the client's redirect_url
        let redis_client: web::Data<redis::Client> = extract().await.map_err(|_| {
            AuthError::InternalServerError("Unable to find session data".to_string())
                .to_server_fn_error()
        })?;
        let OAuthRedirect {
            authorization_code,
            state,
            redirect_url,
        } = handle_request_oauth_token(client_id, username, state, &redis_client).await?;

        println!("Redirecting to: {redirect_url}?code={authorization_code}&state={state}");

        leptos_actix::redirect(
            format!("{redirect_url}?code={authorization_code}&state={state}").as_str(),
        );
    }

    Ok(())
}

#[server(VerifyOtp, "/api")]
async fn verify_otp(
    username: String,
    otp: String,
    client_id: String,
    state: String,
) -> Result<(), ServerFnError<AuthError>> {
    // Get HttpRequest
    let req: actix_web::HttpRequest = extract()
        .await
        .map_err(|_| AuthError::InternalServerError("No context found!".to_string()))?;

    // Extract login_token from user session
    let login_token: String = req
        .get_session()
        .get("otp")
        .map_err(|_| AuthError::InternalServerError("Error getting session!".to_string()))?
        .ok_or_else(|| AuthError::InvalidCredentials)?;

    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;

    handle_verify_otp(&username, otp, login_token, req, db_instance)
        .await
        .map_err(|err| err.to_server_fn_error())?;

    // If not redirected from another app, go to user page
    if client_id.is_empty() && state.is_empty() {
        leptos_actix::redirect("/user");
    } else {
        // If part of OAuth flow, redirect to the client's redirect_url
        let redis_client: web::Data<redis::Client> = extract().await.map_err(|_| {
            AuthError::InternalServerError("Unable to find session data".to_string())
                .to_server_fn_error()
        })?;
        let OAuthRedirect {
            authorization_code,
            state,
            redirect_url,
        } = handle_request_oauth_token(client_id, username, state, &redis_client).await?;

        println!("Redirecting to: {redirect_url}?code={authorization_code}&state={state}");

        leptos_actix::redirect(
            format!("{redirect_url}?code={authorization_code}&state={state}").as_str(),
        );
    }

    Ok(())
}
