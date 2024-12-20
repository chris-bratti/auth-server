use crate::AdminTask;
use crate::AuthError;
use cfg_if::cfg_if;
use leptos::server;
use leptos::ServerFnError;
cfg_if! {
    if #[cfg(feature = "ssr")] {
        use actix_identity::Identity;
        use actix_web::web;
        use leptos_actix::extract;
        use actix_web::HttpRequest;

        use crate::{db::db_helper::DbInstance,
            OAuthRedirect,
            UserBasicInfo,
            server::oauth_handlers::handle_request_oauth_token};
        use crate::server::admin_handlers::handle_get_admin_tasks;
    }
}

#[server]
pub async fn get_user_from_session() -> Result<crate::UserBasicInfo, ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;

    let user: Option<Identity> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Invalid session data!".to_string()).to_server_fn_error()
    })?;

    // If user exists in session, gets User entry from DB
    if let Some(user) = user {
        match db_instance.find_user_by_username(&user.id().unwrap()).await {
            Ok(some_user) => match some_user {
                Some(user) => Ok(UserBasicInfo::from(user)),
                None => Err(AuthError::Error("User not found".to_string()).to_server_fn_error()),
            },
            Err(err) => {
                Err(AuthError::InternalServerError(format!("{}", err)).to_server_fn_error())
            }
        }
    } else {
        println!("No user found in session");
        Err(AuthError::Error("User not found".to_string()).to_server_fn_error())
    }
}

#[server]
pub async fn admin_logged_in() -> Result<bool, ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;

    let admin: Option<Identity> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Invalid session data!".to_string()).to_server_fn_error()
    })?;

    // If user exists in session, gets User entry from DB
    if let Some(admin) = admin {
        match db_instance.get_admin_from_username(&admin.id().unwrap()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    } else {
        println!("No user found in session");
        Err(AuthError::Error("User not found".to_string()).to_server_fn_error())
    }
}

#[server]
pub async fn admin_exists() -> Result<bool, ServerFnError<AuthError>> {
    let (_, db_instance) = get_request_data().await?;

    db_instance
        .admin_exists()
        .map_err(|err| AuthError::from(err).to_server_fn_error())
}

#[server]
pub async fn user_server_side_redirect(
    username: String,
    client_id: Option<String>,
    state: Option<String>,
) -> Result<(), ServerFnError<AuthError>> {
    // If not redirected from another app, go to user page
    if client_id.is_none() && state.is_none() {
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
            redirect_url: url,
        } = handle_request_oauth_token(client_id.unwrap(), username, state.unwrap(), &redis_client)
            .await?;

        leptos_actix::redirect(format!("{url}?code={authorization_code}&state={state}").as_str());
    }
    Ok(())
}

#[cfg(feature = "ssr")]
pub async fn get_request_data(
) -> Result<(HttpRequest, web::Data<DbInstance>), ServerFnError<AuthError>> {
    // Get HttpRequest
    let req: actix_web::HttpRequest = extract()
        .await
        .map_err(|_| AuthError::InternalServerError("No context found!".to_string()))?;
    let db_instance: web::Data<DbInstance> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;

    Ok((req, db_instance))
}

#[server]
pub async fn get_admin_tasks() -> Result<Vec<AdminTask>, ServerFnError<AuthError>> {
    let redis_client: web::Data<redis::Client> = extract().await.map_err(|_| {
        AuthError::InternalServerError("Unable to find session data".to_string())
            .to_server_fn_error()
    })?;

    handle_get_admin_tasks(redis_client)
        .await
        .map_err(|err| ServerFnError::WrappedServerError(err))
}
